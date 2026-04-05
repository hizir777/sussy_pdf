"""
PDF Encryption & Decryption Module (v1.2.0+)

Supports:
- AES-128 & AES-256 encrypted PDFs
- Password recovery attempts
- Encryption metadata extraction
"""


import logging
from io import BytesIO

try:
    from pypdf import PdfReader, PdfWriter
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

logger = logging.getLogger(__name__)


class PDFEncryptionHandler:
    """Handle encrypted PDF files."""

    def __init__(self):
        """Initialize encryption handler."""
        if not PYPDF_AVAILABLE:
            logger.warning(
                "pypdf not installed. "
                "Install with: pip install pypdf"
            )
    
    def is_encrypted(self, pdf_content: bytes) -> bool:
        """Check if PDF is encrypted.

        Args:
            pdf_content: PDF file content
            
        Returns:
            True if encrypted
        """
        if not PYPDF_AVAILABLE:
            # Fallback: check for /Encrypt in content
            return b'/Encrypt' in pdf_content

        try:
            pdf_reader = PdfReader(pdf_content)
            return pdf_reader.is_encrypted
        except Exception as e:
            logger.debug(f"Error checking encryption: {e}")
            return b'/Encrypt' in pdf_content

    def get_encryption_metadata(self, pdf_content: bytes) -> dict:
        """Extract encryption metadata.

        Args:
            pdf_content: PDF file content
            
        Returns:
            Encryption metadata
        """
        metadata = {
            'is_encrypted': False,
            'algorithm': None,
            'key_length': None,
            'access_restrictions': [],
            'requires_password': False,
        }

        if not PYPDF_AVAILABLE:
            metadata['is_encrypted'] = b'/Encrypt' in pdf_content
            return metadata

        try:
            pdf_reader = PdfReader(pdf_content)

            if pdf_reader.is_encrypted:
                metadata['is_encrypted'] = True

                # Extract encryption info
                encrypt_dict = pdf_reader._encryption
                if encrypt_dict:
                    # Algorithm detection
                    if b'/V' in encrypt_dict and b'/R' in encrypt_dict:
                        v = encrypt_dict[b'/V']

                        # V: encryption version
                        if v == 1:
                            metadata['algorithm'] = 'RC4-40'
                            metadata['key_length'] = 40
                        elif v == 2:
                            metadata['algorithm'] = 'RC4-128'
                            metadata['key_length'] = 128
                        elif v == 4:
                            metadata['key_length'] = 128
                            if b'/StmF' in encrypt_dict:
                                metadata['algorithm'] = 'AES-128'
                            else:
                                metadata['algorithm'] = 'RC4'
                        elif v == 5:
                            metadata['algorithm'] = 'AES-256'
                            metadata['key_length'] = 256

                    # Check for password requirements
                    # Owner password vs user password
                    if b'/O' in encrypt_dict or b'/U' in encrypt_dict:
                        metadata['requires_password'] = True

                    # Access restrictions (P = permissions flag)
                    if b'/P' in encrypt_dict:
                        perms = encrypt_dict[b'/P']
                        metadata['access_restrictions'] = self._decode_permissions(perms)

        except Exception as e:
            logger.debug(f"Error extracting encryption metadata: {e}")

        return metadata
    
    def try_decrypt(
        self,
        pdf_content: bytes,
        password: str,
    ) -> bytes | None:
        """Attempt to decrypt PDF with password.

        Args:
            pdf_content: Encrypted PDF content
            password: Password to try

        Returns:
            Decrypted content or None if failed
        """
        if not PYPDF_AVAILABLE:
            logger.warning("pypdf required for decryption")
            return None

        try:
            pdf_reader = PdfReader(pdf_content)

            if not pdf_reader.is_encrypted:
                return pdf_content

            # Try to decrypt with password
            if pdf_reader.decrypt(password):
                logger.info("PDF decrypted successfully")

                # Write decrypted content back
                output = BytesIO()
                writer = PdfWriter()

                for page_num in range(len(pdf_reader.pages)):
                    writer.add_page(pdf_reader.pages[page_num])

                writer.write(output)
                return output.getvalue()
            else:
                logger.debug(f"Decryption failed with password: {password[:3]}...")
                return None

        except Exception as e:
            logger.debug(f"Decryption error: {e}")
            return None

    def try_decrypt_common_passwords(
        self,
        pdf_content: bytes,
        common_passwords: list | None = None,
    ) -> tuple[bool, str | None, bytes | None]:
        """Try decryption with common passwords.

        Args:
            pdf_content: Encrypted PDF content
            common_passwords: List of passwords to try

        Returns:
            (success, used_password, decrypted_content)
        """
        if common_passwords is None:
            common_passwords = [
                '',  # Empty password
                'password',
                'Password',
                'PASSWORD',
                '123456',
                'admin',
                'user',
            ]

        for password in common_passwords:
            decrypted = self.try_decrypt(pdf_content, password)

            if decrypted is not None:
                return True, password, decrypted

        return False, None, None

    @staticmethod
    def _decode_permissions(perms_flag: int) -> list:
        """Decode permission flags from /P entry.

        Args:
            perms_flag: Permission flag value

        Returns:
            List of restricted actions
        """
        restrictions = []

        # PDF permission bits (table from PDF specification)
        if not (perms_flag & (1 << 2)):
            restrictions.append('no_print')
        if not (perms_flag & (1 << 3)):
            restrictions.append('no_modify_contents')
        if not (perms_flag & (1 << 4)):
            restrictions.append('no_copy')
        if not (perms_flag & (1 << 5)):
            restrictions.append('no_add_annotations')
        if not (perms_flag & (1 << 8)):
            restrictions.append('no_fill_forms')
        if not (perms_flag & (1 << 9)):
            restrictions.append('no_extract_text')
        if not (perms_flag & (1 << 10)):
            restrictions.append('no_assemble')
        if not (perms_flag & (1 << 11)):
            restrictions.append('no_print_high_quality')

        return restrictions


# Global encryption handler instance
encryption_handler = PDFEncryptionHandler()
