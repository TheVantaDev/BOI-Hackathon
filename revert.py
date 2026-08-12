import os
import re

def revert_in_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Skipping {filepath}: {e}")
        return

    original = content
    
    content = re.sub(r'\bCognidroid\b', 'Sentinel', content)
    content = re.sub(r'\bcognidroid\b', 'sentinel', content)
    content = re.sub(r'\bCOGNIDROID\b', 'SENTINEL', content)

    if content != original:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Reverted {filepath}")
        except Exception as e:
            print(f"Failed to write {filepath}: {e}")

def walk_dir(start_dir):
    exclude_dirs = {'.git', '__pycache__', 'node_modules', 'venv', '.venv', '.gemini', 'models'}
    exclude_exts = {'.pdf', '.png', '.jpg', '.jpeg', '.zip', '.apk', '.dex', '.tflite', '.keras', '.pkl'}
    for root, dirs, files in os.walk(start_dir):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in exclude_exts:
                continue
            filepath = os.path.join(root, file)
            revert_in_file(filepath)

if __name__ == '__main__':
    project_dir = r"c:\Coding\Python\BOI"
    walk_dir(project_dir)
