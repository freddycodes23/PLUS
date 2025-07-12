const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const ffmpeg = require('fluent-ffmpeg');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/streambox';

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Static file serving
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/thumbnails', express.static(path.join(__dirname, 'thumbnails')));

// Create upload directories
const createDirectories = () => {
  const dirs = ['uploads/videos', 'uploads/audio', 'thumbnails', 'temp'];
  dirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });
};
createDirectories();

// MongoDB connection
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, minlength: 3, maxlength: 30 },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, minlength: 6 },
  avatar: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true }
});

const User = mongoose.model('User', userSchema);

// Media Schema
const mediaSchema = new mongoose.Schema({
  title: { type: String, required: true, maxlength: 200 },
  description: { type: String, maxlength: 1000 },
  category: { type: String, enum: ['video', 'audio', 'podcast'], required: true },
  type: { type: String, enum: ['video', 'audio'], required: true },
  filename: { type: String, required: true },
  originalName: { type: String, required: true },
  fileSize: { type: Number, required: true },
  duration: { type: Number, default: 0 },
  thumbnail: { type: String, default: '' },
  uploader: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  uploaderName: { type: String, required: true },
  uploadDate: { type: Date, default: Date.now },
  views: { type: Number, default: 0 },
  likes: { type: Number, default: 0 },
  dislikes: { type: Number, default: 0 },
  tags: [{ type: String }],
  isPublic: { type: Boolean, default: true },
  isProcessed: { type: Boolean, default: false },
  processingStatus: { type: String, enum: ['pending', 'processing', 'completed', 'failed'], default: 'pending' }
});

const Media = mongoose.model('Media', mediaSchema);

// Comment Schema
const commentSchema = new mongoose.Schema({
  mediaId: { type: mongoose.Schema.Types.ObjectId, ref: 'Media', required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  authorName: { type: String, required: true },
  text: { type: String, required: true, maxlength: 500 },
  createdAt: { type: Date, default: Date.now },
  likes: { type: Number, default: 0 },
  replies: [{
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    authorName: { type: String },
    text: { type: String, maxlength: 500 },
    createdAt: { type: Date, default: Date.now }
  }]
});

const Comment = mongoose.model('Comment', commentSchema);

// Like/Dislike Schema
const ratingSchema = new mongoose.Schema({
  mediaId: { type: mongoose.Schema.Types.ObjectId, ref: 'Media', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['like', 'dislike'], required: true },
  createdAt: { type: Date, default: Date.now }
});

const Rating = mongoose.model('Rating', ratingSchema);

// View tracking schema
const viewSchema = new mongoose.Schema({
  mediaId: { type: mongoose.Schema.Types.ObjectId, ref: 'Media', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  ipAddress: { type: String },
  userAgent: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const View = mongoose.model('View', viewSchema);

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = file.mimetype.startsWith('video') ? 'uploads/videos' : 'uploads/audio';
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 500 * 1024 * 1024 // 500MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|mp4|avi|mov|wmv|flv|webm|mp3|wav|flac|aac|ogg/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only video and audio files are allowed.'));
    }
  }
});

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Optional authentication middleware (for public endpoints that can work with or without auth)
const optionalAuth = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (!err) {
        req.user = user;
      }
    });
  }
  next();
};

// Utility function to generate thumbnails
const generateThumbnail = (inputPath, outputPath) => {
  return new Promise((resolve, reject) => {
    ffmpeg(inputPath)
      .screenshots({
        count: 1,
        folder: path.dirname(outputPath),
        filename: path.basename(outputPath),
        size: '320x240'
      })
      .on('end', () => resolve(outputPath))
      .on('error', reject);
  });
};

// Utility function to get media duration
const getMediaDuration = (filePath) => {
  return new Promise((resolve, reject) => {
    ffmpeg.ffprobe(filePath, (err, metadata) => {
      if (err) {
        reject(err);
      } else {
        resolve(metadata.format.duration || 0);
      }
    });
  });
};

// Routes

// User Authentication Routes
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Media Routes
app.post('/api/media/upload', authenticateToken, upload.single('mediaFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { title, description, category, tags } = req.body;

    if (!title || !category) {
      return res.status(400).json({ error: 'Title and category are required' });
    }

    const mediaType = req.file.mimetype.startsWith('video') ? 'video' : 'audio';
    
    // Get media duration
    let duration = 0;
    try {
      duration = await getMediaDuration(req.file.path);
    } catch (err) {
      console.warn('Could not get media duration:', err);
    }

    // Generate thumbnail for videos
    let thumbnailPath = '';
    if (mediaType === 'video') {
      try {
        const thumbnailFilename = `thumb_${Date.now()}.jpg`;
        thumbnailPath = `thumbnails/${thumbnailFilename}`;
        await generateThumbnail(req.file.path, thumbnailPath);
      } catch (err) {
        console.warn('Could not generate thumbnail:', err);
      }
    }

    // Create media document
    const media = new Media({
      title,
      description: description || '',
      category,
      type: mediaType,
      filename: req.file.filename,
      originalName: req.file.originalname,
      fileSize: req.file.size,
      duration,
      thumbnail: thumbnailPath,
      uploader: req.user.userId,
      uploaderName: req.user.username,
      tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
      isProcessed: true,
      processingStatus: 'completed'
    });

    await media.save();

    res.status(201).json({
      message: 'Media uploaded successfully',
      media: {
        id: media._id,
        title: media.title,
        description: media.description,
        category: media.category,
        type: media.type,
        duration: media.duration,
        thumbnail: media.thumbnail,
        uploader: media.uploaderName,
        uploadDate: media.uploadDate,
        views: media.views,
        likes: media.likes,
        dislikes: media.dislikes
      }
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

app.get('/api/media', optionalAuth, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      category, 
      search, 
      sortBy = 'uploadDate', 
      sortOrder = 'desc' 
    } = req.query;

    const query = { isPublic: true };
    
    if (category && category !== 'all') {
      query.category = category;
    }
    
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const sortOptions = {};
    sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const media = await Media.find(query)
      .sort(sortOptions)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .select('-filename'); // Don't expose actual filename

    const total = await Media.countDocuments(query);

    res.json({
      media,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Get media error:', error);
    res.status(500).json({ error: 'Failed to fetch media' });
  }
});

app.get('/api/media/:id', optionalAuth, async (req, res) => {
  try {
    const media = await Media.findById(req.params.id)
      .populate('uploader', 'username')
      .select('-filename');

    if (!media) {
      return res.status(404).json({ error: 'Media not found' });
    }

    res.json(media);
  } catch (error) {
    console.error('Get media by ID error:', error);
    res.status(500).json({ error: 'Failed to fetch media' });
  }
});

app.get('/api/media/:id/stream', optionalAuth, async (req, res) => {
  try {
    const media = await Media.findById(req.params.id);
    
    if (!media) {
      return res.status(404).json({ error: 'Media not found' });
    }

    const filePath = path.join(__dirname, 'uploads', media.type + 's', media.filename);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Track view
    const viewData = {
      mediaId: media._id,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    };

    if (req.user) {
      viewData.userId = req.user.userId;
    }

    await View.create(viewData);

    // Increment view count
    await Media.findByIdAndUpdate(media._id, { $inc: { views: 1 } });

    // Set appropriate headers for streaming
    const stat = fs.statSync(filePath);
    const fileSize = stat.size;
    const range = req.headers.range;

    if (range) {
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
      const chunksize = (end - start) + 1;
      const file = fs.createReadStream(filePath, { start, end });
      const head = {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Type': media.type === 'video' ? 'video/mp4' : 'audio/mpeg',
      };
      res.writeHead(206, head);
      file.pipe(res);
    } else {
      const head = {
        'Content-Length': fileSize,
        'Content-Type': media.type === 'video' ? 'video/mp4' : 'audio/mpeg',
      };
      res.writeHead(200, head);
      fs.createReadStream(filePath).pipe(res);
    }
  } catch (error) {
    console.error('Stream error:', error);
    res.status(500).json({ error: 'Streaming failed' });
  }
});

app.get('/api/user/media', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;

    const media = await Media.find({ uploader: req.user.userId })
      .sort({ uploadDate: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .select('-filename');

    const total = await Media.countDocuments({ uploader: req.user.userId });

    res.json({
      media,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Get user media error:', error);
    res.status(500).json({ error: 'Failed to fetch user media' });
  }
});

app.delete('/api/media/:id', authenticateToken, async (req, res) => {
  try {
    const media = await Media.findById(req.params.id);
    
    if (!media) {
      return res.status(404).json({ error: 'Media not found' });
    }

    if (media.uploader.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Delete physical files
    const filePath = path.join(__dirname, 'uploads', media.type + 's', media.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    if (media.thumbnail) {
      const thumbnailPath = path.join(__dirname, media.thumbnail);
      if (fs.existsSync(thumbnailPath)) {
        fs.unlinkSync(thumbnailPath);
      }
    }

    // Delete from database
    await Media.findByIdAndDelete(req.params.id);
    
    // Delete related comments and ratings
    await Comment.deleteMany({ mediaId: req.params.id });
    await Rating.deleteMany({ mediaId: req.params.id });
    await View.deleteMany({ mediaId: req.params.id });

    res.json({ message: 'Media deleted successfully' });
  } catch (error) {
    console.error('Delete media error:', error);
    res.status(500).json({ error: 'Failed to delete media' });
  }
});

// Comment Routes
app.get('/api/media/:id/comments', async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;

    const comments = await Comment.find({ mediaId: req.params.id })
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .populate('author', 'username');

    const total = await Comment.countDocuments({ mediaId: req.params.id });

    res.json({
      comments,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Get comments error:', error);
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

app.post('/api/media/:id/comments', authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;

    if (!text || text.trim().length === 0) {
      return res.status(400).json({ error: 'Comment text is required' });
    }

    const media = await Media.findById(req.params.id);
    if (!media) {
      return res.status(404).json({ error: 'Media not found' });
    }

    const comment = new Comment({
      mediaId: req.params.id,
      author: req.user.userId,
      authorName: req.user.username,
      text: text.trim()
    });

    await comment.save();

    res.status(201).json({
      message: 'Comment added successfully',
      comment: {
        id: comment._id,
        author: comment.authorName,
        text: comment.text,
        createdAt: comment.createdAt,
        likes: comment.likes
      }
    });
  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

app.delete('/api/comments/:id', authenticateToken, async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.id);
    
    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }

    if (comment.author.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    await Comment.findByIdAndDelete(req.params.id);
    
    res.json({ message: 'Comment deleted successfully' });
  } catch (error) {
    console.error('Delete comment error:', error);
    res.status(500).json({ error: 'Failed to delete comment' });
  }
});

// Rating Routes
app.post('/api/media/:id/rate', authenticateToken, async (req, res) => {
  try {
    const { type } = req.body; // 'like' or 'dislike'
    
    if (!['like', 'dislike'].includes(type)) {
      return res.status(400).json({ error: 'Invalid rating type' });
    }

    const media = await Media.findById(req.params.id);
    if (!media) {
      return res.status(404).json({ error: 'Media not found' });
    }

    // Check if user already rated
    const existingRating = await Rating.findOne({
      mediaId: req.params.id,
      userId: req.user.userId
    });

    if (existingRating) {
      if (existingRating.type === type) {
        // Remove rating if same type
        await Rating.findByIdAndDelete(existingRating._id);
        await Media.findByIdAndUpdate(req.params.id, { $inc: { [type + 's']: -1 } });
        return res.json({ message: 'Rating removed' });
      } else {
        // Update rating type
        existingRating.type = type;
        await existingRating.save();
        
        // Update media counts
        const oldType = type === 'like' ? 'dislike' : 'like';
        await Media.findByIdAndUpdate(req.params.id, { 
          $inc: { [type + 's']: 1, [oldType + 's']: -1 } 
        });
        
        return res.json({ message: 'Rating updated' });
      }
    }

    // Create new rating
    const rating = new Rating({
      mediaId: req.params.id,
      userId: req.user.userId,
      type
    });

    await rating.save();
    await Media.findByIdAndUpdate(req.params.id, { $inc: { [type + 's']: 1 } });

    res.json({ message: 'Rating added successfully' });
  } catch (error) {
    console.error('Rating error:', error);
    res.status(500).json({ error: 'Failed to add rating' });
  }
});

// Analytics Routes
app.get('/api/analytics/overview', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const totalMedia = await Media.countDocuments({ uploader: userId });
    const totalViews = await Media.aggregate([
      { $match: { uploader: mongoose.Types.ObjectId(userId) } },
      { $group: { _id: null, totalViews: { $sum: '$views' } } }
    ]);
    
    const totalComments = await Comment.countDocuments({
      mediaId: { $in: await Media.find({ uploader: userId }).distinct('_id') }
    });
    
    const totalLikes = await Media.aggregate([
      { $match: { uploader: mongoose.Types.ObjectId(userId) } },
      { $group: { _id: null, totalLikes: { $sum: '$likes' } } }
    ]);

    res.json({
      totalMedia,
      totalViews: totalViews[0]?.totalViews || 0,
      totalComments,
      totalLikes: totalLikes[0]?.totalLikes || 0
    });
  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// Search Routes
app.get('/api/search', async (req, res) => {
  try {
    const { q, category, page = 1, limit = 20 } = req.query;
    
    if (!q) {
      return res.status(400).json({ error: 'Search query is required' });
    }

    const query = {
      isPublic: true,
      $or: [
        { title: { $regex: q, $options: 'i' } },
        { description: { $regex: q, $options: 'i' } },
        { tags: { $in: [new RegExp(q, 'i')] } }
      ]
    };

    if (category && category !== 'all') {
      query.category = category;
    }

    const media = await Media.find(query)
      .sort({ views: -1, uploadDate: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .select('-filename');

    const total = await Media.countDocuments(query);

    res.json({
      media,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total,
      query: q
    });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Error:', error);
  
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large' });
    }
  }
  
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`StreamBox backend server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});

module.exports = app;