
import os
import hashlib
import random
import string

def create_benign_test_file(filename, size_kb=50):
    """Create a benign test file for educational demonstration"""
    
    # Create a simple PE-like structure (not actually executable)
    content = b"MZ"  # PE header signature
    content += b"\x00" * 58  # PE header padding
    content += b"PE\x00\x00"  # PE signature
    
    # Add some dummy sections
    content += b".text\x00\x00\x00"  # Section name
    content += b".data\x00\x00\x00"  # Section name
    content += b".rsrc\x00\x00\x00"  # Section name
    
    # Add some benign strings
    benign_strings = [
        b"Hello World\x00",
        b"Microsoft Corporation\x00",
        b"Windows NT\x00",
        b"kernel32.dll\x00",
        b"user32.dll\x00",
        b"GetProcAddress\x00",
        b"LoadLibrary\x00"
    ]
    
    for s in benign_strings:
        content += s
    
    # Pad to desired size
    current_size = len(content)
    target_size = size_kb * 1024
    
    if current_size < target_size:
        padding = b"\x00" * (target_size - current_size)
        content += padding
    
    # Write file
    os.makedirs('test_samples', exist_ok=True)
    filepath = os.path.join('test_samples', filename)
    
    with open(filepath, 'wb') as f:
        f.write(content)
    
    # Calculate hashes
    md5_hash = hashlib.md5(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()
    
    return {
        'filename': filename,
        'path': filepath,
        'size': len(content),
        'md5': md5_hash,
        'sha256': sha256_hash
    }

def create_test_samples():
    """Create various test samples for educational purposes"""
    
    print("Creating educational test samples...")
    print("=" * 50)
    
    samples = []
    
    # Create benign samples
    benign_samples = [
        'calculator.exe',
        'notepad.exe', 
        'system_utility.dll',
        'graphics_lib.dll',
        'text_editor.exe'
    ]
    
    for sample in benign_samples:
        info = create_benign_test_file(sample, random.randint(30, 100))
        samples.append(info)
        print(f"✅ Created: {sample} ({info['size']} bytes)")
    
    # Create info file
    info_content = """# Educational Test Samples

These are benign test files created for educational demonstration of malware analysis concepts.

## Files Created:
"""
    
    for sample in samples:
        info_content += f"\n- **{sample['filename']}**"
        info_content += f"\n  - Size: {sample['size']} bytes"
        info_content += f"\n  - MD5: {sample['md5']}"
        info_content += f"\n  - SHA256: {sample['sha256'][:32]}..."
        info_content += f"\n  - Purpose: Educational demonstration\n"
    
    info_content += """
## Usage:
- Upload these files through the web interface
- Observe how the analysis tools work
- Learn about static analysis techniques
- Understand ML classification concepts

⚠️ **Important**: These are educational samples only!
"""
    
    with open('test_samples/README.md', 'w') as f:
        f.write(info_content)
    
    print(f"\n✅ Created {len(samples)} test samples in 'test_samples/' directory")
    print("📖 See test_samples/README.md for details")
    
    return samples

if __name__ == "__main__":
    create_test_samples()
