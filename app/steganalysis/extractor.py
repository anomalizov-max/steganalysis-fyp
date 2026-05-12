"""
Data Extraction Module
Extracts hidden data from images using various steganography tools
"""

import os
import subprocess
import numpy as np
from PIL import Image
from typing import Dict, Optional

class DataExtractor:
    """Extracts hidden data from images"""
    
    def __init__(self):
        self.name = "Data Extractor"
    
    def extract(self, image_path: str, output_dir: str) -> Dict:
        """
        Attempt to extract hidden data using multiple methods.
        Order: append-after-EOF → LSB → steghide → OpenStego patterns
        """
        results = {
            'extracted': False,
            'method': None,
            'output_path': None,
            'data_size': 0,
            'data_preview': None,
            'data_type': None,
            'hidden_filename': None
        }

        # ① Check for appended data after image EOF (copy /b method)
        append_result = self._extract_appended_data(image_path, output_dir)
        if append_result['extracted']:
            return append_result

        # ② Try LSB extraction
        lsb_result = self._extract_lsb(image_path, output_dir)
        if lsb_result['extracted']:
            return lsb_result

        # ③ Try steghide (if available)
        steghide_result = self._extract_steghide(image_path, output_dir)
        if steghide_result['extracted']:
            return steghide_result

        # ④ Try OpenStego patterns
        openstego_result = self._extract_openstego_pattern(image_path, output_dir)
        if openstego_result['extracted']:
            return openstego_result

        return results

    
    # Known file signatures: (magic_bytes, file_extension, description)
    # Longer/more specific signatures are listed first to avoid mismatches.
    FILE_SIGNATURES = [
        # Archives
        (b'PK\x03\x04',         '.zip',  'ZIP Archive'),
        (b'Rar!\x1a\x07',       '.rar',  'RAR Archive'),
        (b'7z\xbc\xaf\x27\x1c', '.7z',   '7-Zip Archive'),
        (b'\x1f\x8b',           '.gz',   'Gzip Archive'),
        (b'MSCF',               '.cab',  'CAB Archive'),
        # Executables
        (b'MZ',                 '.exe',  'Windows Executable (EXE/DLL)'),
        (b'\x7fELF',            '.elf',  'Linux Executable (ELF)'),
        # Documents
        (b'%PDF',               '.pdf',  'PDF Document'),
        (b'\xd0\xcf\x11\xe0',   '.doc',  'MS Office Document'),
        # Images
        (b'\x89PNG',            '.png',  'PNG Image'),
        (b'\xff\xd8\xff',       '.jpg',  'JPEG Image'),
        (b'GIF89a',             '.gif',  'GIF Image'),
        (b'GIF87a',             '.gif',  'GIF Image'),
        (b'BM',                 '.bmp',  'BMP Image'),
        # Audio/Video
        (b'RIFF',               '.wav',  'WAV Audio'),
        (b'ID3',                '.mp3',  'MP3 Audio'),
        # Text / Data
        (b'<?xml',              '.xml',  'XML File'),
        (b'<!DOCTYPE',          '.html', 'HTML File'),
        (b'<html',              '.html', 'HTML File'),
        (b'{"',                 '.json', 'JSON File'),
    ]

    # End-of-message delimiter used by the embedding tool
    DELIMITER = '#####'

    # ------------------------------------------------------------------ #
    #  Append-after-EOF extraction (Windows "copy /b image + file" trick) #
    # ------------------------------------------------------------------ #
    def _extract_appended_data(self, image_path: str, output_dir: str) -> Dict:
        """
        Detect and extract data that has been appended AFTER the image's
        official end-of-file marker.

        Supported formats:
          JPEG  — data after the 0xFF 0xD9 End-of-Image (EOI) marker
          PNG   — data after the IEND chunk (last 12 bytes of a valid PNG)
          BMP   — data after the declared file size in the BMP header
          GIF   — data after the 0x3B trailer byte

        This is exactly what `copy /b image.jpg + secret.txt out.jpg` does.
        """
        try:
            with open(image_path, 'rb') as f:
                raw = f.read()

            appended = None
            fmt = None

            # --- JPEG: find last 0xFF 0xD9 ---
            if raw[:3] == b'\xff\xd8\xff':
                eoi = raw.rfind(b'\xff\xd9')
                if eoi != -1 and eoi + 2 < len(raw):
                    appended = raw[eoi + 2:]
                    fmt = 'JPEG'

            # --- PNG: find IEND chunk end ---
            elif raw[:4] == b'\x89PNG':
                iend = raw.rfind(b'IEND')
                if iend != -1:
                    after_iend = iend + 8   # 'IEND' (4) + CRC (4)
                    if after_iend < len(raw):
                        appended = raw[after_iend:]
                        fmt = 'PNG'

            # --- GIF: find 0x3B trailer ---
            elif raw[:6] in (b'GIF89a', b'GIF87a'):
                trailer = raw.rfind(b'\x3b')
                if trailer != -1 and trailer + 1 < len(raw):
                    appended = raw[trailer + 1:]
                    fmt = 'GIF'

            # --- BMP: use declared file size from header ---
            elif raw[:2] == b'BM' and len(raw) > 6:
                declared_size = int.from_bytes(raw[2:6], 'little')
                if declared_size < len(raw):
                    appended = raw[declared_size:]
                    fmt = 'BMP'

            if appended and len(appended) >= 4:
                # Strip leading/trailing whitespace / nulls that copy /b adds
                appended = appended.strip(b'\x00\r\n ')
                if len(appended) < 4:
                    return {'extracted': False}

                data_type, ext = self._detect_data_type(appended)
                hidden_name = self._detect_hidden_filename(appended, ext)
                safe_name = hidden_name.replace('/', '_').replace('\\', '_')
                output_path = os.path.join(output_dir, safe_name)

                with open(output_path, 'wb') as f:
                    f.write(appended)

                # ── Step 2: File Carving ──────────────────────────────────
                # Scan the raw blob for known magic-byte signatures so that
                # multi-payload attacks (PDF + ZIP + EXE inside one blob)
                # are listed individually instead of showing a single .bin.
                carved = self._carve_files_from_blob(appended)

                return {
                    'extracted': True,
                    'method': f'Append-after-EOF ({fmt})',
                    'output_path': output_path,
                    'data_size': len(appended),
                    'data_preview': self._get_data_preview(appended),
                    'data_type': data_type,
                    'hidden_filename': hidden_name,
                    'carved_files': carved          # list of dicts, may be empty
                }
        except Exception:
            pass

        return {'extracted': False}

    def _extract_lsb(self, image_path: str, output_dir: str) -> Dict:
        """
        Extract data hidden using LSB method.

        Strategy (in order):
          1. OpenStego header: detect OpenStego-style embedded files with filename.
          2. Delimiter-based: scan bits, stop when '#####' marker is found.
          3. Length-header: read 32-bit length prefix then that many bytes.
          (Raw fallback removed — it only produced noise.)
        """
        try:
            img = Image.open(image_path)

            # --- Palette-mode images ---
            if img.mode == 'P':
                palette_bits = self._extract_palette_lsb_bits(img)
                extracted_bytes = self._extract_until_delimiter(palette_bits)
                if extracted_bytes is None:
                    extracted_bytes = self._extract_with_length_header(palette_bits)
                if extracted_bytes is not None and len(extracted_bytes) > 0:
                    data_type, ext = self._detect_data_type(extracted_bytes)
                    hidden_name = self._detect_hidden_filename(extracted_bytes, ext)
                    safe_name = hidden_name.replace('/', '_').replace('\\', '_')
                    output_path = os.path.join(output_dir, safe_name)
                    with open(output_path, 'wb') as f:
                        f.write(extracted_bytes)
                    return {
                        'extracted': True,
                        'method': 'LSB Extraction (Palette)',
                        'output_path': output_path,
                        'data_size': len(extracted_bytes),
                        'data_preview': self._get_data_preview(extracted_bytes),
                        'data_type': data_type,
                        'hidden_filename': hidden_name
                    }

            # --- RGB / other modes ---
            if img.mode != 'RGB':
                img = img.convert('RGB')

            img_array = np.array(img)
            lsb_bits = self._extract_lsb_bits(img_array)

            # --- Strategy 1: OpenStego header detection ---
            openstego_result = self._extract_openstego_lsb(lsb_bits, output_dir)
            if openstego_result.get('extracted'):
                return openstego_result

            # --- Strategy 2: Delimiter-based ---
            extracted_bytes = self._extract_until_delimiter(lsb_bits)

            # --- Strategy 3: Length-header ---
            if extracted_bytes is None:
                extracted_bytes = self._extract_with_length_header(lsb_bits)

            # Only accept if the content is genuinely meaningful
            if extracted_bytes is not None and self._is_valid_data(extracted_bytes):
                data_type, ext = self._detect_data_type(extracted_bytes)
                hidden_name = self._detect_hidden_filename(extracted_bytes, ext)
                safe_name = hidden_name.replace('/', '_').replace('\\', '_')
                output_path = os.path.join(output_dir, safe_name)

                with open(output_path, 'wb') as f:
                    f.write(extracted_bytes)

                return {
                    'extracted': True,
                    'method': 'LSB Extraction',
                    'output_path': output_path,
                    'data_size': len(extracted_bytes),
                    'data_preview': self._get_data_preview(extracted_bytes),
                    'data_type': data_type,
                    'hidden_filename': hidden_name
                }
        except Exception:
            pass

        return {'extracted': False, 'method': 'LSB Extraction', 'hidden_filename': None}

    def _detect_hidden_filename(self, data: bytes, ext: str) -> Optional[str]:
        """
        Try to recover the original filename from the embedded payload.
        Priority:
          1. 'filename:' prefix convention
          2. Null-terminated filename at start
          3. Descriptive fallback using the real detected extension
        """
        import re

        # Convention 1: "filename:" prefix
        try:
            head = data[:128].decode('utf-8', errors='replace')
            m = re.match(r'^([\w\-. ]{1,64}):', head)
            if m:
                candidate = m.group(1).strip()
                if '.' in candidate or len(candidate) >= 4:
                    return candidate
        except Exception:
            pass

        # Convention 2: null-terminated filename
        try:
            null_idx = data.index(b'\x00')
            if 2 <= null_idx <= 128:
                candidate = data[:null_idx].decode('utf-8', errors='replace').strip()
                if re.match(r'^[\w\-. ]{2,64}$', candidate) and '.' in candidate:
                    return candidate
        except (ValueError, Exception):
            pass

        # Convention 3: descriptive fallback using the REAL detected extension
        type_names = {
            # Text
            '.txt':  'secret.txt',
            '.xml':  'hidden_data.xml',
            '.json': 'hidden_data.json',
            '.html': 'hidden_page.html',
            # Documents
            '.pdf':  'hidden_document.pdf',
            '.doc':  'hidden_document.doc',
            # Images
            '.jpg':  'hidden_image.jpg',
            '.png':  'hidden_image.png',
            '.gif':  'hidden_image.gif',
            '.bmp':  'hidden_image.bmp',
            # Archives
            '.zip':  'hidden_archive.zip',
            '.rar':  'hidden_archive.rar',
            '.7z':   'hidden_archive.7z',
            '.gz':   'hidden_archive.gz',
            '.cab':  'hidden_archive.cab',
            # Audio
            '.mp3':  'hidden_audio.mp3',
            '.wav':  'hidden_audio.wav',
            # Executables
            '.exe':  'hidden_file.exe',
            '.dll':  'hidden_file.dll',
            '.elf':  'hidden_file.elf',
        }
        if ext in type_names:
            return type_names[ext]
        # Generic fallback — keep the real extension so it's usable
        return f'hidden_file{ext}' if ext and ext != '.bin' else 'hidden_data.bin'

    def _extract_openstego_lsb(self, bits: np.ndarray, output_dir: str) -> Dict:
        """
        Try to extract data embedded using OpenStego format.

        OpenStego header (all values big-endian, embedded as LSBs):
          - Magic: 0x4F70537400 ('OpSt\\x00') — first 5 bytes
          - 1 byte: header version
          - 2 bytes: channel flags
          - 4 bytes: data length (number of payload bytes)
          - 2 bytes: filename length
          - N bytes: filename (UTF-8)
          - Payload bytes follow

        Also handles simplified variants that just store:
          [4 bytes: length][filename bytes][\\x00][payload]
        """
        try:
            # Read first 200 bytes to inspect header
            max_header_bits = min(len(bits), 200 * 8)
            header_bytes = bytearray()
            for i in range(max_header_bits // 8):
                byte_val = 0
                for bit in bits[i * 8: i * 8 + 8]:
                    byte_val = (byte_val << 1) | int(bit)
                header_bytes.append(byte_val)

            # --- OpenStego magic check ---
            MAGIC = b'OpSt'
            if header_bytes[:4] == MAGIC:
                offset = 6  # skip magic (4) + version (1) + channel (1)
                data_len = int.from_bytes(header_bytes[offset:offset+4], 'big')
                offset += 4
                fname_len = int.from_bytes(header_bytes[offset:offset+2], 'big')
                offset += 2

                if 0 < fname_len < 200 and 0 < data_len < 10_000_000:
                    # Extract full content
                    total_bytes_needed = offset + fname_len + data_len
                    all_bytes = bytearray()
                    for i in range(min(total_bytes_needed, len(bits) // 8)):
                        byte_val = 0
                        for bit in bits[i * 8: i * 8 + 8]:
                            byte_val = (byte_val << 1) | int(bit)
                        all_bytes.append(byte_val)

                    filename = all_bytes[offset: offset + fname_len].decode('utf-8', errors='replace').strip('\x00')
                    payload  = bytes(all_bytes[offset + fname_len: offset + fname_len + data_len])

                    if len(payload) == data_len and filename:
                        safe_name = filename.replace('/', '_').replace('\\', '_')
                        output_path = os.path.join(output_dir, safe_name)
                        with open(output_path, 'wb') as f:
                            f.write(payload)
                        data_type, _ = self._detect_data_type(payload)
                        return {
                            'extracted': True,
                            'method': 'LSB Extraction (OpenStego)',
                            'output_path': output_path,
                            'data_size': len(payload),
                            'data_preview': self._get_data_preview(payload),
                            'data_type': data_type,
                            'hidden_filename': filename
                        }
        except Exception:
            pass

        return {'extracted': False}

    def _extract_lsb_bits(self, img_array: np.ndarray) -> np.ndarray:
        """
        Extract LSB bits from image array
        """
        # Get LSBs from all channels
        lsb_bits = img_array & 1
        
        # Flatten in reading order (row by row, channel by channel)
        height, width, channels = img_array.shape
        bits = []
        
        for i in range(height):
            for j in range(width):
                for c in range(channels):
                    bits.append(lsb_bits[i, j, c])
        
        return np.array(bits, dtype=np.uint8)

    def _extract_palette_lsb_bits(self, img) -> np.ndarray:
        """
        Extract LSB bits from a palette-mode (P) image.
        In palette images, pixel values are palette indices (0-255).
        Hidden data is embedded in the LSB of each index.
        """
        pixels = np.array(img, dtype=np.uint8)   # shape: (height, width)
        flat = pixels.flatten()
        return (flat & 1).astype(np.uint8)


    def _extract_until_delimiter(self, bits: np.ndarray) -> Optional[bytes]:
        """
        Convert LSB bits to bytes 8-at-a-time and stop as soon as the
        '#####' end-of-message delimiter is encountered.

        Returns the payload bytes *before* the delimiter, or None if the
        delimiter is not found within the first 500 KB of capacity.
        """
        delimiter_bytes = self.DELIMITER.encode('ascii')  # b'#####'
        max_bytes = min(len(bits) // 8, 512_000)          # safety cap

        buffer = bytearray()
        for i in range(max_bytes):
            # Group exactly 8 bits, MSB first
            byte_bits = bits[i * 8: i * 8 + 8]
            if len(byte_bits) < 8:
                break
            byte_value = 0
            for bit in byte_bits:
                byte_value = (byte_value << 1) | int(bit)
            buffer.append(byte_value)

            # Check for delimiter at the end of the buffer
            if buffer.endswith(delimiter_bytes):
                payload = bytes(buffer[: -len(delimiter_bytes)])
                return payload if len(payload) > 0 else None

        return None  # delimiter not found

    def _extract_with_length_header(self, bits: np.ndarray) -> Optional[bytes]:
        """
        Try to extract data that has a 32-bit length header (common in stego
        tools).  Returns extracted bytes or None if header is invalid.
        """
        if len(bits) < 32:
            return None

        # Read 32-bit big-endian length
        message_length = 0
        for bit in bits[:32]:
            message_length = (message_length << 1) | int(bit)

        # Sanity check
        if message_length < 10 or message_length > 100_000:
            return None

        total_bits_needed = 32 + message_length * 8
        if len(bits) < total_bits_needed:
            return None

        return self._bits_to_bytes(bits[32:total_bits_needed], max_bytes=message_length)

    def _bits_to_bytes(self, bits: np.ndarray, max_bytes: int = 10_000) -> bytes:
        """
        Convert a flat bit array to bytes, grouping every 8 bits MSB-first.
        """
        num_bytes = min(len(bits) // 8, max_bytes)
        extracted = bytearray(num_bytes)
        for i in range(num_bytes):
            byte_value = 0
            for bit in bits[i * 8: i * 8 + 8]:
                byte_value = (byte_value << 1) | int(bit)
            extracted[i] = byte_value
        return bytes(extracted)
    
    def _is_valid_data(self, data: bytes, min_length: int = 10) -> bool:
        """
        Check if extracted data appears to be valid steganographic content.
        Accepts known file signatures unconditionally; applies strict text
        checks otherwise to avoid false positives from random LSB noise.
        """
        if len(data) < min_length:
            return False

        # Accept any known file signature immediately
        for magic, _, _ in self.FILE_SIGNATURES:
            if data.startswith(magic):
                return True

        # Strict text check: must be valid UTF-8, mostly printable, word-like
        try:
            text = data.decode('utf-8', errors='strict')
            if len(text) < 20:
                return False

            printable_ratio = sum(
                c.isprintable() or c in '\n\r\t' for c in text
            ) / len(text)
            if printable_ratio < 0.95:
                return False

            if len(text.split()) < 3:
                return False

            alpha_count = sum(c.isalpha() for c in text)
            if alpha_count > 0:
                common = sum(c.lower() in 'etaoinshrdlu' for c in text if c.isalpha())
                if common / alpha_count < 0.3:
                    return False

            return True
        except (UnicodeDecodeError, Exception):
            pass

        return False
    
    def _get_data_preview(self, data: bytes, preview_length: int = 5_000) -> str:
        """
        Return a human-readable preview of the extracted payload.
        - Text payloads are shown as decoded strings (up to preview_length chars).
        - Binary / file payloads are shown as formatted hex + file-type header.
        """
        # --- Binary file: label it and show hex ---
        for magic, _, description in self.FILE_SIGNATURES:
            if data.startswith(magic):
                hex_lines = [
                    '[{} file detected — showing first 256 bytes as hex]'.format(description)
                ]
                chunk = data[:256]
                for i in range(0, len(chunk), 16):
                    row = chunk[i:i + 16]
                    hex_part = ' '.join(f'{b:02x}' for b in row)
                    asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
                    hex_lines.append(f'{i:04x}  {hex_part:<48}  {asc_part}')
                if len(data) > 256:
                    hex_lines.append(f'\n[... {len(data) - 256} more bytes — download to view full file]')
                return '\n'.join(hex_lines)

        # --- Text payload ---
        for encoding in ('utf-8', 'ascii', 'latin-1'):
            try:
                text = data.decode(encoding, errors='strict')
                ratio = sum(
                    c.isprintable() or c in '\n\r\t' for c in text[:500]
                ) / min(500, len(text))
                if ratio > 0.9:
                    if len(text) > preview_length:
                        return (
                            text[:preview_length]
                            + f'\n\n[... truncated {len(data) - preview_length} more characters]'
                        )
                    return text
            except Exception:
                continue

        # --- Generic binary hex dump ---
        chunk = data[:256]
        hex_lines = ['[Binary data — hex dump]']
        for i in range(0, len(chunk), 16):
            row = chunk[i:i + 16]
            hex_part = ' '.join(f'{b:02x}' for b in row)
            asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
            hex_lines.append(f'{i:04x}  {hex_part:<48}  {asc_part}')
        if len(data) > 256:
            hex_lines.append(f'\n[... {len(data) - 256} more bytes not shown]')
        return '\n'.join(hex_lines)
    
    def _detect_data_type(self, data: bytes):
        """
        Detect the type of extracted data.

        Returns:
            Tuple[str, str]: (human-readable description, file extension)
            e.g. ('ZIP Archive', '.zip') or ('Plain Text', '.txt')
        """
        for magic, ext, description in self.FILE_SIGNATURES:
            if data.startswith(magic):
                return description, ext

        # Try plain text
        try:
            text = data.decode('utf-8', errors='strict')
            ratio = sum(
                c.isprintable() or c in '\n\r\t' for c in text[:500]
            ) / min(500, len(text))
            if ratio > 0.9:
                return 'Plain Text', '.txt'
        except Exception:
            pass

        return 'Binary Data', '.bin'
    
    def _extract_steghide(self, image_path: str, output_dir: str) -> Dict:
        """
        Try to extract using steghide (requires steghide to be installed)
        """
        try:
            output_path = os.path.join(output_dir, 'extracted_steghide.bin')
            
            # Try without password first
            cmd = ['steghide', 'extract', '-sf', image_path, '-xf', output_path, '-p', '']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=10,
                text=True
            )
            
            if result.returncode == 0 and os.path.exists(output_path):
                with open(output_path, 'rb') as f:
                    data = f.read()
                
                preview = self._get_data_preview(data)
                data_type = self._detect_data_type(data)
                
                return {
                    'extracted': True,
                    'method': 'Steghide',
                    'output_path': output_path,
                    'data_size': len(data),
                    'data_preview': preview,
                    'data_type': data_type
                }
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # steghide not installed or timed out
            pass
        except Exception as e:
            pass
        
        return {'extracted': False, 'method': 'Steghide'}
    
    def _extract_openstego_pattern(self, image_path: str, output_dir: str) -> Dict:
        """
        Try to detect and extract OpenStego patterns
        """
        # OpenStego uses LSB but with specific patterns
        # This is a simplified version
        return {'extracted': False, 'method': 'OpenStego Pattern'}

    # ------------------------------------------------------------------ #
    #  Step 2 — File Carving: scan blob for embedded file signatures      #
    # ------------------------------------------------------------------ #
    def _carve_files_from_blob(self, blob: bytes) -> list:
        """
        Scan *blob* for known file-magic signatures and return a list of
        carved file descriptors.

        Each descriptor is a dict::

            {
                'filename':    str,   # e.g. 'carved_01_PDF Document.pdf'
                'description': str,   # e.g. 'PDF Document'
                'extension':   str,   # e.g. '.pdf'
                'offset':      int,   # byte offset inside the blob
                'size':        int,   # bytes from this sig to the next (or EOF)
                'magic_hex':   str,   # e.g. '25 50 44 46'
            }

        If fewer than 2 distinct signatures are found the result is an empty
        list — in that case the blob itself is already correctly typed and the
        caller should just display it as a single file.
        """
        # Collect all (offset, magic, ext, description) hits
        hits = []
        for magic, ext, description in self.FILE_SIGNATURES:
            start = 0
            while True:
                pos = blob.find(magic, start)
                if pos == -1:
                    break
                hits.append((pos, magic, ext, description))
                start = pos + 1  # allow overlapping searches

        if not hits:
            return []

        # Sort by offset; deduplicate hits at the same offset (keep longest magic)
        hits.sort(key=lambda h: (h[0], -len(h[1])))
        deduped = []
        last_offset = -1
        for pos, magic, ext, description in hits:
            if pos == last_offset:
                continue   # already have a (longer) match at this offset
            deduped.append((pos, magic, ext, description))
            last_offset = pos

        # Need at least 2 different signature regions to call it "multi-payload"
        if len(deduped) < 2:
            return []

        # Build carved file descriptors
        carved = []
        for idx, (pos, magic, ext, description) in enumerate(deduped):
            # Size = bytes from this offset up to the start of the next hit (or EOF)
            next_pos = deduped[idx + 1][0] if idx + 1 < len(deduped) else len(blob)
            size = next_pos - pos

            magic_hex = ' '.join(f'{b:02X}' for b in magic)
            filename = f'carved_{idx + 1:02d}_{description.replace(" ", "_")}{ext}'

            carved.append({
                'filename':    filename,
                'description': description,
                'extension':   ext,
                'offset':      pos,
                'size':        size,
                'magic_hex':   magic_hex,
            })

        return carved
