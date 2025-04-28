import os
import pickle
import hashlib
import logging
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
import magic  # python-magic for file type detection
import io

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("secure_file_system.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SecureFileSystem")

class MalwareDetector:
    """Detect malware in files using machine learning"""
    
    def __init__(self, model_path=None):
        """Initialize the malware detector with a trained model or create a new one"""
        if model_path and os.path.exists(model_path):
            self.model = joblib.load(model_path)
            logger.info(f"Loaded malware detection model from {model_path}")
        else:
            # Create a simple model for demonstration purposes
            # In production, you would use a well-trained model
            self.model = RandomForestClassifier(n_estimators=100)
            logger.warning("Using a new untrained model. This is not recommended for production.")
            self._train_demo_model()
    
    def _train_demo_model(self):
        """Train a simple demo model - NOT FOR PRODUCTION USE"""
        # This is just a placeholder implementation
        # In a real system, you would use a proper dataset of malware features
        
        # Synthetic features (file size, entropy, exe content marker, etc.)
        X = np.array([
            [250000, 7.2, 0, 0.1, 0],  # Safe document
            [1500000, 7.8, 0, 0.2, 0],  # Safe large document
            [50000, 7.1, 0, 0.05, 0],   # Safe small document
            [450000, 7.9, 1, 0.8, 1],   # Malware
            [120000, 4.2, 1, 0.7, 1],   # Malware
            [300000, 7.5, 1, 0.85, 1],  # Malware
        ])
        
        # Labels: 0 for safe, 1 for malware
        y = np.array([0, 0, 0, 1, 1, 1])
        
        # Train the model
        self.model.fit(X, y)
        logger.info("Demo model trained (NOT FOR PRODUCTION USE)")
    
    def extract_features(self, file_data):
        """Extract features from a file for malware detection"""
        # Calculate file size
        file_size = len(file_data)
        
        # Calculate entropy (measure of randomness)
        entropy = self._calculate_entropy(file_data)
        
        # Check for executable content
        exe_marker = 1 if b'MZ' in file_data[:10] or b'PE' in file_data[:100] else 0
        
        # Calculate ratio of printable to non-printable characters
        printable_ratio = sum(32 <= b <= 126 for b in file_data[:1000]) / min(1000, len(file_data))
        
        # Check for suspicious strings
        suspicious_strings = 1 if any(s in file_data for s in 
                                      [b'cmd.exe', b'powershell', b'eval(', b'shell_exec']) else 0
        
        return np.array([[file_size, entropy, exe_marker, printable_ratio, suspicious_strings]])
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of the data"""
        if not data:
            return 0
        
        # Count byte frequencies
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0
        for count in byte_counts.values():
            probability = count / len(data)
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    def is_malware(self, file_data):
        """Detect if a file is malware based on extracted features"""
        features = self.extract_features(file_data)
        prediction = self.model.predict(features)[0]
        probability = self.model.predict_proba(features)[0][1]  # Probability of being malware
        
        logger.info(f"Malware scan result: {'Malware' if prediction == 1 else 'Safe'} "
                  f"(Probability: {probability:.2f})")
        
        return prediction == 1, probability
    
    def save_model(self, model_path):
        """Save the current model to a file"""
        joblib.dump(self.model, model_path)
        logger.info(f"Model saved to {model_path}")


class FileEncryptor:
    """Handle AES-256 encryption and decryption of files"""
    
    @staticmethod
    def generate_key(password, salt=None):
        """Generate a 256-bit encryption key from a password"""
        if salt is None:
            salt = os.urandom(16)
        
        # Use key derivation function to generate a strong key from the password
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return key, salt
    
    @staticmethod
    def encrypt_file(file_data, password):
        """Encrypt file data using AES-256"""
        # Generate a key from the password
        key, salt = FileEncryptor.generate_key(password)
        
        # Generate a random IV (initialization vector)
        iv = os.urandom(16)
        
        # Create an encryptor object
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        
        # Pad the data to be a multiple of block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        
        # Encrypt the data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Prepend the salt and IV to the encrypted data
        result = salt + iv + encrypted_data
        
        logger.info(f"File encrypted successfully (Size: {len(file_data)} → {len(result)})")
        return result
    
    @staticmethod
    def decrypt_file(encrypted_data, password):
        """Decrypt file data using AES-256"""
        # Extract the salt and IV from the encrypted data
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        actual_encrypted_data = encrypted_data[32:]
        
        # Generate the key from the password and salt
        key, _ = FileEncryptor.generate_key(password, salt)
        
        # Create a decryptor object
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        padded_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()
        
        # Unpad the data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        logger.info(f"File decrypted successfully (Size: {len(encrypted_data)} → {len(data)})")
        return data


class SecureFileSystem:
    """Main system that handles file uploads, malware scanning, and encryption"""
    
    def __init__(self, storage_dir="secure_files", malware_model_path=None):
        """Initialize the secure file system"""
        self.storage_dir = storage_dir
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir)
            logger.info(f"Created storage directory: {storage_dir}")
        
        self.malware_detector = MalwareDetector(malware_model_path)
        self.file_index = {}
        self._load_file_index()
        
        logger.info("Secure File System initialized")
    
    def _load_file_index(self):
        """Load the file index from disk if it exists"""
        index_path = os.path.join(self.storage_dir, "file_index.pkl")
        if os.path.exists(index_path):
            try:
                with open(index_path, 'rb') as f:
                    self.file_index = pickle.load(f)
                logger.info(f"Loaded file index with {len(self.file_index)} entries")
            except Exception as e:
                logger.error(f"Error loading file index: {e}")
                self.file_index = {}
    
    def _save_file_index(self):
        """Save the file index to disk"""
        index_path = os.path.join(self.storage_dir, "file_index.pkl")
        try:
            with open(index_path, 'wb') as f:
                pickle.dump(self.file_index, f)
            logger.info(f"Saved file index with {len(self.file_index)} entries")
        except Exception as e:
            logger.error(f"Error saving file index: {e}")
    
    def process_file(self, file_path, file_name=None, password="default_password"):
        """Process a file: check for malware, encrypt if safe, and store"""
        # If file_name is not provided, use the basename of file_path
        if file_name is None:
            file_name = os.path.basename(file_path)
        
        # Read the file
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        return self.process_file_data(file_data, file_name, password)
    
    def process_file_data(self, file_data, file_name, password="default_password"):
        """Process file data: check for malware, encrypt if safe, and store"""
        # Detect file type
        file_type = magic.from_buffer(file_data[:1024], mime=True)
        logger.info(f"Processing file: {file_name} ({file_type}, {len(file_data)} bytes)")
        
        # Check for malware
        is_malware, malware_probability = self.malware_detector.is_malware(file_data)
        
        if is_malware:
            logger.warning(f"MALWARE DETECTED: {file_name} (Probability: {malware_probability:.2f})")
            return {
                "status": "error",
                "message": f"Malware detected with probability {malware_probability:.2f}. File not stored.",
                "file_name": file_name
            }
        
        # Encrypt the file
        encrypted_data = FileEncryptor.encrypt_file(file_data, password)
        
        # Generate a secure filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        secure_filename = hashlib.sha256(f"{file_name}_{timestamp}".encode()).hexdigest() + ".enc"
        
        # Save the encrypted file
        file_path = os.path.join(self.storage_dir, secure_filename)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Update the file index
        self.file_index[secure_filename] = {
            "original_name": file_name,
            "upload_time": timestamp,
            "file_type": file_type,
            "size": len(file_data),
            "encrypted_size": len(encrypted_data)
        }
        
        # Save the updated file index
        self._save_file_index()
        
        logger.info(f"File safely encrypted and stored: {file_name} → {secure_filename}")
        
        return {
            "status": "success",
            "message": "File securely encrypted and stored.",
            "file_name": file_name,
            "secure_id": secure_filename,
            "upload_time": timestamp,
            "file_type": file_type
        }
    
    def retrieve_file(self, secure_id, password="default_password"):
        """Retrieve and decrypt a file by its secure ID"""
        if secure_id not in self.file_index:
            logger.error(f"File not found: {secure_id}")
            return None, None
        
        # Get file info
        file_info = self.file_index[secure_id]
        original_name = file_info["original_name"]
        
        # Read the encrypted file
        file_path = os.path.join(self.storage_dir, secure_id)
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt the file
            file_data = FileEncryptor.decrypt_file(encrypted_data, password)
            
            logger.info(f"File retrieved and decrypted: {secure_id} → {original_name}")
            return file_data, original_name
        
        except Exception as e:
            logger.error(f"Error retrieving file {secure_id}: {e}")
            return None, None
    
    def list_files(self):
        """List all files in the secure file system"""
        return [
            {
                "secure_id": secure_id,
                "original_name": info["original_name"],
                "upload_time": info["upload_time"],
                "file_type": info["file_type"],
                "size": info["size"]
            }
            for secure_id, info in self.file_index.items()
        ]
    
    def delete_file(self, secure_id):
        """Delete a file from the secure file system"""
        if secure_id not in self.file_index:
            logger.error(f"File not found for deletion: {secure_id}")
            return False
        
        file_path = os.path.join(self.storage_dir, secure_id)
        try:
            os.remove(file_path)
            original_name = self.file_index[secure_id]["original_name"]
            del self.file_index[secure_id]
            self._save_file_index()
            logger.info(f"File deleted: {secure_id} ({original_name})")
            return True
        except Exception as e:
            logger.error(f"Error deleting file {secure_id}: {e}")
            return False


# Create a simple command-line interface to demonstrate the functionality
def main():
    print("Secure File System with Encryption & Malware Detection")
    print("======================================================")
    
    # Initialize the secure file system
    secure_fs = SecureFileSystem()
    
    while True:
        print("\nOptions:")
        print("1. Upload a file")
        print("2. Download a file")
        print("3. List all files")
        print("4. Delete a file")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == '1':
            file_path = input("Enter the path to the file: ")
            if not os.path.exists(file_path):
                print(f"Error: File not found at {file_path}")
                continue
            
            password = input("Enter encryption password (leave blank for default): ")
            if not password:
                password = "default_password"
            
            result = secure_fs.process_file(file_path, password=password)
            
            if result["status"] == "success":
                print(f"Success! File stored with secure ID: {result['secure_id']}")
            else:
                print(f"Error: {result['message']}")
        
        elif choice == '2':
            secure_id = input("Enter the secure ID of the file: ")
            password = input("Enter decryption password (leave blank for default): ")
            if not password:
                password = "default_password"
            
            file_data, original_name = secure_fs.retrieve_file(secure_id, password)
            
            if file_data is None:
                print("Error: Could not retrieve the file.")
                continue
            
            save_path = input(f"Enter path to save '{original_name}' (leave blank for current dir): ")
            if not save_path:
                save_path = original_name
            
            with open(save_path, 'wb') as f:
                f.write(file_data)
            
            print(f"File saved to {save_path}")
        
        elif choice == '3':
            files = secure_fs.list_files()
            
            if not files:
                print("No files stored in the system.")
                continue
            
            print("\nStored Files:")
            print(f"{'Secure ID':<15} | {'Original Name':<30} | {'Upload Time':<20} | {'File Type':<20} | {'Size':<10}")
            print("-" * 100)
            
            for file in files:
                print(f"{file['secure_id'][:12]}... | {file['original_name'][:28]} | {file['upload_time']} | {file['file_type'][:18]} | {file['size']} B")
        
        elif choice == '4':
            secure_id = input("Enter the secure ID of the file to delete: ")
            if secure_fs.delete_file(secure_id):
                print("File deleted successfully.")
            else:
                print("Error: Could not delete the file.")
        
        elif choice == '5':
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")


# Example usage with a Flask web application
def create_flask_app():
    from flask import Flask, request, jsonify, send_file
    
    app = Flask(__name__)
    secure_fs = SecureFileSystem()
    
    @app.route('/upload', methods=['POST'])
    def upload_file():
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No selected file'}), 400
        
        password = request.form.get('password', 'default_password')
        
        # Read the file data
        file_data = file.read()
        
        # Process the file
        result = secure_fs.process_file_data(file_data, file.filename, password)
        
        return jsonify(result)
    
    @app.route('/download/<secure_id>', methods=['GET'])
    def download_file(secure_id):
        password = request.args.get('password', 'default_password')
        
        file_data, original_name = secure_fs.retrieve_file(secure_id, password)
        
        if file_data is None:
            return jsonify({'status': 'error', 'message': 'File not found or decryption failed'}), 404
        
        return send_file(
            io.BytesIO(file_data),
            download_name=original_name,
            as_attachment=True
        )
    
    @app.route('/files', methods=['GET'])
    def list_files():
        files = secure_fs.list_files()
        return jsonify({'status': 'success', 'files': files})
    
    @app.route('/delete/<secure_id>', methods=['DELETE'])
    def delete_file(secure_id):
        success = secure_fs.delete_file(secure_id)
        
        if success:
            return jsonify({'status': 'success', 'message': 'File deleted'})
        else:
            return jsonify({'status': 'error', 'message': 'File not found or deletion failed'}), 404
    
    return app


if __name__ == "__main__":
    main()