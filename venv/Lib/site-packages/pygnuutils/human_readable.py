from enum import Flag

SIZES_TO_EXP = {
    '': 10 ** 0,
    'K': 10 ** 3,
    'M': 10 ** 6,
    'G': 10 ** 9,
    'T': 10 ** 12,
    'P': 10 ** 15,
    'E': 10 ** 18,
    'Z': 10 ** 21,
    'Y': 10 ** 24,
}

EXP_TO_SIZE = {v: k for k, v in SIZES_TO_EXP.items()}


class HumanReadableOption(Flag):
    CEILING = 0
    ROUND_TO_NEAREST = 1
    FLOOR = 2
    GROUP_DIGITS = 4
    SUPPRESS_POINT_ZERO = 8
    AUTOSCALE = 16
    BASE_1024 = 32
    SPACE_BEFORE_UNIT = 64
    SI = 128
    B = 256

    def is_ceiling(self):
        return self.ROUND_TO_NEAREST not in self and self.FLOOR not in self


def _parse_block_size_and_unit(specs):
    block_size = -1
    for i in range(len(specs)):
        if i == 1 and specs[i].lower() in ('x', 'o', 'b'):
            continue
        try:
            block_size = int(specs[:i + 1], 0)
        except ValueError:
            return block_size, specs[i:]
    return block_size, ''


def _parse_size_unit(unit, block_size, opts):
    if not unit:
        return block_size, opts
    if block_size == -1:
        opts |= HumanReadableOption.SI
        block_size = 1
    block_size = block_size * SIZES_TO_EXP[unit[0].upper()]
    unit = unit[1:]
    if unit == 'B':
        opts |= HumanReadableOption.B
    elif unit == 'iB':
        opts |= HumanReadableOption.BASE_1024
    elif unit:
        raise ValueError()
    return block_size, opts


def parse_specs(specs):
    if not specs:
        return 0, HumanReadableOption.CEILING

    opts = HumanReadableOption.CEILING
    if specs[0] == '\'':
        opts |= HumanReadableOption.GROUP_DIGITS
        specs = specs[1:]
    if specs == 'human-readable':
        opts |= HumanReadableOption.AUTOSCALE | HumanReadableOption.SI | HumanReadableOption.BASE_1024
        return 1, opts
    if specs == 'si':
        opts |= HumanReadableOption.AUTOSCALE | HumanReadableOption.SI
        return 1, opts

    block_size, unit = _parse_block_size_and_unit(specs)
    return _parse_size_unit(unit, block_size, opts)


def size_from_int(amt, tenths, rounding, base, opts):
    buf = ''
    exponent = -1
    if HumanReadableOption.AUTOSCALE in opts:
        exponent = 0
        if base <= amt:
            for exponent in range(len(EXP_TO_SIZE)):
                if base > amt:
                    break
                r10 = (amt % base) * 10 + tenths
                r2 = (r10 % base) * 2 + (rounding >> 1)
                amt //= base
                tenths = r10 // base
                rounding = int(r2 + rounding != 0) if (r2 < base) else 2 + int((base < r2 + rounding))
            if amt < 10:
                if (HumanReadableOption.ROUND_TO_NEAREST in opts and 2 < rounding + (tenths & 1)) or (
                        opts.is_ceiling() and rounding > 0):
                    tenths += 1
                    rounding = 0
                    if tenths == 10:
                        amt += 1
                        tenths = 0
                if amt < 10 and (tenths or HumanReadableOption.SUPPRESS_POINT_ZERO not in opts):
                    buf = f'.{tenths}'
                    tenths = 0
                    rounding = 0
    if (HumanReadableOption.ROUND_TO_NEAREST in opts and 5 < tenths + int(0 < rounding + (amt & 1))) or (
            opts.is_ceiling() and rounding + tenths > 0):
        amt += 1
        if HumanReadableOption.AUTOSCALE in opts and amt == base and exponent < len(EXP_TO_SIZE):
            exponent += 1
            if HumanReadableOption.SUPPRESS_POINT_ZERO not in opts:
                buf = '.0'
            amt = 1
    return str(amt) + buf, exponent


def size_from_float(damt, base, opts):
    exponent = -1
    if HumanReadableOption.AUTOSCALE not in opts:
        buf = f'{damt:.0f}'
    else:
        e = base
        exponent = 1
        for exponent in range(1, len(EXP_TO_SIZE)):
            if e * base > damt:
                break
            e *= base
        damt /= e
        if HumanReadableOption.SUPPRESS_POINT_ZERO in opts:
            buf = f'{damt:.0f}'
        else:
            buf = f'{damt:.1f}'
    return buf, exponent


def _group_buffer(buffer):
    parts = buffer.split('.')
    integer = list(parts[0])
    for i in range(len(integer) - 3, 0, -3):
        integer.insert(i, ',')
    return ''.join(integer + parts[1:])


def _size_indication(exponent, base, opts, to_block_size):
    buf = ''
    if exponent < 0:
        exponent = 0
        power = 1
        while power < to_block_size:
            exponent += 1
            if exponent == len(EXP_TO_SIZE):
                break
            power = power * base
    if (exponent or HumanReadableOption.B in opts) and HumanReadableOption.SPACE_BEFORE_UNIT in opts:
        buf += ' '
    if exponent:
        buf += 'k' if (HumanReadableOption.BASE_1024 not in opts and exponent == 1) else EXP_TO_SIZE[
            10 ** (3 * exponent)]
    if HumanReadableOption.B in opts:
        if HumanReadableOption.BASE_1024 in opts:
            buf += 'i'
        buf += 'B'
    return buf


def human_readable(size: int, opts: HumanReadableOption, from_block_size=1, to_block_size=1):
    base = 1024 if opts & HumanReadableOption.BASE_1024 else 1000
    if to_block_size <= from_block_size and from_block_size % to_block_size == 0:
        multiplier = from_block_size // to_block_size
        buf, exponent = size_from_int(size * multiplier, 0, 0, base, opts)
    elif from_block_size and to_block_size % from_block_size == 0:
        divisor = to_block_size // from_block_size
        r10 = (size % divisor) * 10
        r2 = (r10 % divisor) * 2
        amt = size // divisor
        tenths = r10 // divisor
        rounding = int(0 < r2) if (r2 < divisor) else 2 + int(divisor < r2)
        buf, exponent = size_from_int(amt, tenths, rounding, base, opts)
    else:
        buf, exponent = size_from_float(size * (from_block_size / to_block_size), base, opts)

    if HumanReadableOption.GROUP_DIGITS in opts:
        buf = _group_buffer(buf)
    if HumanReadableOption.SI in opts:
        buf += _size_indication(exponent, base, opts, to_block_size)
    return buf
