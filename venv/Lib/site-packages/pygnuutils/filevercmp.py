def _handle_special(s1, s2):
    # Easy comparison to see if strings are identical.
    if s1 == s2:
        return 0
    # Special handle for "", "." and "..".
    if not s1:
        return -1
    if not s2:
        return 1
    if s1 == '.':
        return -1
    if s2 == '.':
        return 1
    if s1 == '..':
        return -1
    if s2 == '..':
        return 1
    # Special handle for other hidden files.
    if s1[0] == '.' and s2[0] != '.':
        return -1
    if s1[0] != '.' and s2[0] == '.':
        return 1
    return None


def match_suffix(str_: str):
    match = ''
    read_alpha = False
    while str_:
        if read_alpha:
            read_alpha = False
            if not str_[0].isalpha() and str_[0] != '~':
                match = ''
        elif str_[0] == '.':
            read_alpha = True
            if not match:
                match = str_
        elif not str_[0].isalnum() and str_[0] != '~':
            match = ''
        str_ = str_[1:]
    return match


def order(c: str):
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == '~':
        return -1
    return ord(c) + 256


def verrevcmp(s1: str, s2: str):
    while s1 or s2:
        first_diff = 0
        while (s1 and not s1[0].isdigit()) or (s2 and not s2[0].isdigit()):
            s1_c = order(s1[0]) if s1 else 0
            s2_c = order(s2[0]) if s2 else 0
            if s1_c != s2_c:
                return s1_c - s2_c
            s1 = s1[1:]
            s2 = s2[1:]
        s1 = s1.lstrip('0')
        s2 = s2.lstrip('0')
        while (s1 and s1[0].isdigit()) and (s2 and s2[0].isdigit()):
            if not first_diff:
                first_diff = ord(s1[0]) - ord(s2[0])
            s1 = s1[1:]
            s2 = s2[1:]
        if s1 and s1[0].isdigit():
            return 1
        if s2 and s2[0].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def filevercmp(s1, s2):
    special_handle = _handle_special(s1, s2)
    if special_handle is not None:
        return special_handle

    if s1[0] == s2[0] == '.':
        s1 = s1[1:]
        s2 = s2[1:]
    # "cut" file suffixes
    s1_suffix = match_suffix(s1)
    s2_suffix = match_suffix(s2)
    s1_len = len(s1) - len(s1_suffix)
    s2_len = len(s2) - len(s2_suffix)
    if (s1_suffix or s2_suffix) and s1_len == s2_len and s1[:s1_len] == s2[:s1_len]:
        s1_len = len(s1)
        s2_len = len(s2)
    result = verrevcmp(s1[:s1_len], s2[:s2_len])
    simple_cmp = 1 if s1 > s2 else -1
    return result if result else simple_cmp
