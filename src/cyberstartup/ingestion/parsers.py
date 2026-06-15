import torch
import hashlib
import os

class TextParser:
    """Parses text inputs (like STIX indicators or forum posts) into tensor representations."""
    def __init__(self, embedding_dim=768):
        self.embedding_dim = embedding_dim

    def parse(self, text_input):
        """
        Parses a single string or list of strings into actual text representations.
        Returns a list of raw text strings read from files.
        """
        if isinstance(text_input, str):
            texts = [text_input]
        else:
            texts = text_input

        num_ttps = len(texts)
        if num_ttps == 0:
            return []

        parsed_texts = []
        for text in texts:
            if os.path.exists(text):
                with open(text, 'r', encoding='utf-8') as f:
                    parsed_texts.append(f.read())
            else:
                parsed_texts.append(text)

        return parsed_texts


class HexParser:
    """Parses arbitrary files (e.g., unauthorized software binaries) by reading hexadecimal/byte values."""
    def __init__(self, embedding_dim=256):
        self.embedding_dim = embedding_dim

    def parse(self, file_input):
        """
        Reads actual files, processes byte values, and outputs a (num_ttps, 256) float tensor.
        """
        if isinstance(file_input, str):
            files = [file_input]
        else:
            files = file_input

        num_ttps = len(files)
        if num_ttps == 0:
            return torch.zeros((0, self.embedding_dim), dtype=torch.float32)

        tensor_data = []
        for file_path in files:
            vec = [0.0] * self.embedding_dim
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        if content:
                            for i, byte in enumerate(content):
                                vec[i % self.embedding_dim] += float(byte) / 255.0
                except Exception as e:
                    print(f"HexParser error reading {file_path}: {e}")

            # Normalize values to prevent large spikes
            max_v = max(vec) if max(vec) > 0 else 1.0
            vec = [v / max_v for v in vec]
            tensor_data.append(vec)

        return torch.tensor(tensor_data, dtype=torch.float32)


class ImageParser:
    """Parses images (like architecture diagrams) into tensor representations."""
    def __init__(self, embedding_dim=512):
        self.embedding_dim = embedding_dim

    def parse(self, file_input):
        """
        Reads actual image files, resizes, flattens/hashes into a (num_ttps, 512) float tensor.
        """
        try:
            from PIL import Image
            has_pil = True
        except ImportError:
            has_pil = False

        if isinstance(file_input, str):
            files = [file_input]
        else:
            files = file_input

        num_ttps = len(files)
        if num_ttps == 0:
            return torch.zeros((0, self.embedding_dim), dtype=torch.float32)

        tensor_data = []
        for file_path in files:
            vec = [0.0] * self.embedding_dim
            if os.path.exists(file_path):
                try:
                    if has_pil:
                        with Image.open(file_path) as img:
                            # Resize to aggregate features
                            img = img.convert('RGB').resize((32, 32))
                            pixels = list(img.getdata())
                            for i, (r, g, b) in enumerate(pixels):
                                val = (r + g + b) / (3.0 * 255.0)
                                vec[i % self.embedding_dim] += val
                    else:
                        # Heuristic baseline standard library approach for reading raw bytes
                        with open(file_path, 'rb') as f:
                            content = f.read()
                            for i, byte in enumerate(content):
                                vec[i % self.embedding_dim] += float(byte) / 255.0
                except Exception as e:
                    print(f"ImageParser error reading {file_path}: {e}")

            max_v = max(vec) if max(vec) > 0 else 1.0
            vec = [v / max_v for v in vec]
            tensor_data.append(vec)

        return torch.tensor(tensor_data, dtype=torch.float32)
