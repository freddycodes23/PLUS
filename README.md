StreamPLUS - Full-Stack Media Streaming Platform
StreamPLUS is a complete, full-stack web application for uploading, streaming, and interacting with media content. This platform provides a seamless and feature-rich experience for users to browse, upload, and play videos and audio, engage with content through comments and ratings, and manage their own media library.

The architecture combines a robust Node.js backend for handling all data, authentication, and file processing, with a sleek and responsive vanilla JavaScript frontend for an intuitive user experience.

Architecture Overview
The application is built on a classic client-server model:

Backend (Node.js/Express): The powerful core of the application. It manages the database, handles user authentication, processes media uploads (including thumbnail generation), serves streaming content, and provides a comprehensive RESTful API.

Frontend (HTML/CSS/JS): A dynamic and responsive single-page application (SPA) that interacts with the backend API to display media, handle user input, and manage playback.

# Core Technologies
Backend
Node.js: A JavaScript runtime for building the server-side application.

Express.js: A minimal and flexible Node.js web application framework that provides a robust set of features for web and mobile applications.

MongoDB: A NoSQL database used to store all application data, including user info, media metadata, and comments.

Mongoose: An Object Data Modeling (ODM) library for MongoDB and Node.js, used to manage relationships between data and provide schema validation.

JWT (JSON Web Tokens): Used for securing API endpoints and managing user authentication.

Multer: A Node.js middleware for handling multipart/form-data, used primarily for uploading files.

fluent-ffmpeg: A library for advanced media processing, used here for generating video thumbnails and extracting media duration.

Security: Includes helmet for securing HTTP headers, cors for managing cross-origin requests, bcrypt for password hashing, and express-rate-limit to prevent brute-force attacks.

# Frontend
HTML5: Provides the core structure and content of the application.

CSS3: Handles all styling, including a modern design with gradients, responsive layouts, and smooth animations.

JavaScript (ES6+): Powers all the dynamic and interactive features of the platform, fetching data from the backend API and rendering it dynamically.

# Key Features
User Authentication: Secure user registration and login system using JWT.

Media Upload & Processing: Users can upload video and audio files. The backend processes videos to generate thumbnails and extracts media duration.

Efficient Media Streaming: Supports HTTP range requests for efficient video and audio streaming, allowing users to seek through content.

Content Discovery: Browse all public media, with server-side support for searching, filtering by category, and sorting.

Personal Content Management: A "My Content" section where authenticated users can view and delete their own uploads.

Interactive Engagement: Users can post comments on media, as well as like or dislike content.

Detailed Analytics: Authenticated users can view basic analytics for their uploaded content, such as total views, likes, and comments.

Secure & Robust: The backend includes important security measures like rate limiting, password hashing, and protection against common web vulnerabilities.

Responsive Design: The frontend is fully responsive, ensuring a great user experience on desktops, tablets, and mobile devices.

Getting Started
To get the full-stack StreamPLUS application running locally, you need to set up both the backend server and the frontend.

# Prerequisites
Node.js (v14 or higher)

npm (comes with Node.js)

MongoDB: A running instance of MongoDB (local or cloud-based, like MongoDB Atlas).

FFmpeg: This must be installed on the server machine for thumbnail generation and media processing. You can download it from ffmpeg.org.

# Backend Setup
Clone the Repository:

git clone <your-repository-url>
cd <repository-folder>

Install Dependencies:
Navigate to the project directory (where package.json is located) and run:

npm install

# Configure Environment Variables:
Create a .env file in the root of the project directory and add the following configuration variables. Replace the placeholder values with your own.

# Server Configuration
PORT=3000

# MongoDB Connection
MONGODB_URI=mongodb://localhost:27017/streamPLUS

# JWT Secret Key
JWT_SECRET=your-super-secret-and-long-jwt-key

# Run the Backend Server:

For development with automatic reloading (requires nodemon):

npm run dev

For production:

npm start

The backend server should now be running on http://localhost:3000.

# Frontend Setup
Save the Frontend Code:
Save the provided HTML code as index.html.

# Update API Endpoints:
The provided media_streaming_app.html file uses a mock, in-memory JavaScript array (mediaLibrary) for data. To connect it to your live backend, you must modify the JavaScript code within the <script> tag.

Replace the mock data and functions with fetch() calls to your backend API. For example, to load media, you would change renderMediaGrid() to fetch from http://localhost:3000/api/media.

# Run the Frontend:
Open the index.html file in a modern web browser. Once you have updated the JavaScript to communicate with your backend, the application will be fully functional.

API Endpoints Overview
The backend provides the following RESTful API endpoints:

# Authentication

POST /api/register: Create a new user account.

POST /api/login: Log in a user and receive a JWT.

# Media

POST /api/media/upload: Upload a new media file (requires authentication).

GET /api/media: Get a paginated list of all public media.

GET /api/media/:id: Get details for a single media item.

GET /api/media/:id/stream: Stream a media file.

GET /api/user/media: Get all media uploaded by the authenticated user.

DELETE /api/media/:id: Delete a media item (requires ownership).

# Comments & Ratings

GET /api/media/:id/comments: Get comments for a media item.

POST /api/media/:id/comments: Add a comment (requires authentication).

DELETE /api/comments/:id: Delete a comment (requires ownership).

POST /api/media/:id/rate: Like or dislike a media item (requires authentication).

 # Other

GET /api/search: Search for media based on a query.

GET /api/analytics/overview: Get analytics for the authenticated user's content.

GET /health: A health check endpoint for the server.
_Algouation_
