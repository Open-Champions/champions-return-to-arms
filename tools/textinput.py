"""Read tool inputs consistently across UTF-8 and BOM-marked Windows text files.

PowerShell 5 redirects native command output to UTF-16. Newer PowerShell and the
Python generator use UTF-8. Do not guess other encodings: invalid input must fail.
"""


def text_lines(path, errors='strict'):
    with open(path, 'rb') as raw:
        prefix = raw.read(4)
    if prefix.startswith((b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff')):
        raise ValueError(f'{path}: UTF-32 input is unsupported; save as UTF-8')
    encoding = 'utf-16' if prefix.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'
    with open(path, encoding=encoding, errors=errors) as source:
        for line in source:
            if '\x00' in line:
                raise ValueError(f'{path}: embedded NUL; save text as UTF-8 or BOM-marked UTF-16')
            yield line
