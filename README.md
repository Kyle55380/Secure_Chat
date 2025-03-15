# Secure Chat Application

This is a **Python-based encrypted chat application** that enables secure communication between two users using **AES and RSA encryption**. The application supports both hosting a chat server and connecting as a client.

## Features
✅ **End-to-end encryption** using **AES-256** for messages and **RSA-2048** for key exchange  
✅ **Secure key exchange** with RSA encryption  
✅ **Graphical User Interface (GUI)** using **Tkinter**  
✅ **Supports both Host and Client modes**  
✅ **Multi-threaded for real-time message exchange**  
✅ **Custom styling for a modern look**  

---

## Installation
### **1. Install Dependencies**
Make sure you have Python installed. Then install required dependencies:
```bash
pip install rsa pycryptodome
```

---

## Usage
### **Run as Host (Server Mode)**
```bash
python GUI.py
```
- Select **"Host"** mode
- Start chat (wait for client connection)

### **Run as Client (Connect Mode)**
```bash
python GUI.py
```
- Enter the **host's IP address**
- Select **"Connect"** mode
- Start chat!

---

## How It Works
1. **RSA Key Generation**  
   - Both users generate **2048-bit RSA key pairs**.
   - They **exchange their public keys**.
2. **AES Key Exchange**  
   - The **host** generates a **256-bit AES key**.
   - It is **encrypted using the recipient’s RSA public key**.
   - The client **decrypts the AES key** with their private key.
3. **Encrypted Chat Messages**  
   - Messages are encrypted with **AES-GCM** before transmission.
   - Only the intended recipient can decrypt the messages.

---

## File Structure
```
📁 SecureChat
│── GUI.py         # Main chat application with GUI
│── encryption.py  # Encryption functions (AES + RSA)
│── README.md      # Project documentation
```

---

## Encryption Details
- **AES Encryption (AES-256-GCM)**:
  - Each message is encrypted with a **unique AES nonce** for security.
  - Ensures **confidentiality & integrity** with authentication tags.
- **RSA Encryption (RSA-2048)**:
  - Used for **secure AES key exchange**.
  - Prevents **man-in-the-middle attacks**.

---

## Security Notes
🔒 **NEVER share your private key!**  
🔒 **Always verify the public key of your chat partner before exchanging AES keys.**  
🔒 **Use a secure network to prevent interception.**  

---

## License
This project is licensed under the **MIT License**.

