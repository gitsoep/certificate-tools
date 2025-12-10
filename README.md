# CSR Generator Web Application

A simple and secure web application built with Flask that generates Certificate Signing Requests (CSR) and private keys for SSL/TLS certificates.

## Features

- 🔐 Generate CSR and private key pairs
- 📝 User-friendly web interface
- 🎨 Modern, responsive design
- 📋 One-click copy to clipboard
- 💾 Download generated files
- 🔑 Support for multiple key sizes (2048, 3072, 4096 bits)
- ✅ All standard certificate fields supported

## Requirements

- Python 3.7+
- Flask
- cryptography library

## Installation

1. Clone the repository:
```bash
git clone https://github.com/gitsoep/csrgenerator.git
cd csrgenerator
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Development Mode

1. Start the Flask development server:
```bash
python app.py
```

### Production Mode

1. Using Gunicorn (recommended):
```bash
gunicorn --bind 0.0.0.0:5001 --workers 4 app:app
```

Or use the startup script:
```bash
chmod +x start.sh
./start.sh
```

2. Using Docker:
```bash
docker-compose up -d
```

3. Open your web browser and navigate to:
```
http://localhost:5000
```

3. Fill in the certificate details:
   - **Common Name (CN)** - Required (e.g., example.com or *.example.com)
   - **Organization (O)** - Your company name
   - **Organizational Unit (OU)** - Your department (e.g., IT)
   - **Country (C)** - Two-letter country code (e.g., US)
   - **State/Province (ST)** - State or province name
   - **City/Locality (L)** - City name
   - **Email Address** - Contact email
   - **Key Size** - Choose 2048, 3072, or 4096 bits

4. Click "Generate CSR and Private Key"

5. Copy or download your private key and CSR

## Security Notes

⚠️ **Important**: 
- Keep your private key secure and never share it with anyone
- Store the private key in a safe location - you'll need it when installing the SSL certificate
- This application generates keys locally and does not send any data to external servers
- For production use, consider adding authentication and running over HTTPS

## Project Structure

```
csrgenerator/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
└── templates/
    ├── index.html        # Main form page
    └── result.html       # Results display page
```

## How It Works

1. The application uses the `cryptography` library to generate RSA private keys
2. A Certificate Signing Request is created with the provided subject information
3. Both the private key and CSR are serialized to PEM format
4. The results are displayed in the browser with options to copy or download

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
