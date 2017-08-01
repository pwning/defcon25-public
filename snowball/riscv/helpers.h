// Macros and inline functions
static uint32_t read_32(inst_t *inst)
{
    uint32_t result;
    const uint8_t *ptr = inst->bytes + inst->size;
#ifdef BIG_ENDIAN
    result = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3] << 0);
#else
    result = (ptr[0] << 0) | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24);
#endif
    inst->size += 4;
    return result;
}

static uint32_t read_24(inst_t *inst)
{
    uint32_t result;
    const uint8_t *ptr = inst->bytes + inst->size;
#ifdef BIG_ENDIAN
    result = (ptr[0] << 16) | (ptr[1] << 8) | (ptr[2] << 0);
#else
    result = (ptr[0] << 0) | (ptr[1] << 8) | (ptr[2] << 16);
#endif
    inst->size += 3;
    return result;
}

static uint16_t read_16(inst_t *inst)
{
    uint16_t result;
    const uint8_t *ptr = inst->bytes + inst->size;
#ifdef BIG_ENDIAN
    result = (ptr[0] << 8) | (ptr[1] << 0);
#else
    result = (ptr[0] << 0) | (ptr[1] << 8);
#endif
    inst->size += 2;
    return result;
}

static uint8_t read_8(inst_t *inst)
{
    uint8_t result;
    const uint8_t *ptr = inst->bytes + inst->size;
    result = ptr[0];
    inst->size += 1;
    return result;
}

// Extract bits [offset, offset+count)
#define EXTRACT(src, offset, count) (((src) >> (offset)) & ((1 << (count))-1))

// Extract bits from inst->insn to a field (marks field as used)
#define FIELD(name, offset, count) do { inst->name = EXTRACT(inst->insn, offset, count); inst->used_##name = 1; } while (0)

// Concatenate extracted bits on to a field (appends them to the end)
#define CONCAT(name, offset, count) do { inst->name = (inst->name << (count)) | EXTRACT(inst->insn, offset, count); } while (0)

// Sign-extend an integer with fewer than 32 bits
#define SIGN_EXTEND(name, count) do { inst->name = ((int32_t)inst->name << (32 - count)) >> (32 - count); } while (0)

// Helper to reverse bits in an integer
static uint32_t reverse_bits(uint32_t x)
{
    x = ((x >> 1) & 0x55555555u) | ((x & 0x55555555u) << 1);
    x = ((x >> 2) & 0x33333333u) | ((x & 0x33333333u) << 2);
    x = ((x >> 4) & 0x0f0f0f0fu) | ((x & 0x0f0f0f0fu) << 4);
    x = ((x >> 8) & 0x00ff00ffu) | ((x & 0x00ff00ffu) << 8);
    x = ((x >> 16) & 0xffffu) | ((x & 0xffffu) << 16);
    return x;
}

static void clear_used(inst_t *inst)
{
    // Clear fields.
    memset(inst->_fields, 0, (char *)inst + sizeof(inst_t) - inst->_fields);
}

// Append a comma, or a space if this is the first operand
#define PRINT_SEP() do { strcat(inst->str, first ? " " : ", "); first = 0; } while (0)

// Append a register field (if it is marked as used)
#define PRINT_REGISTER(name) do { if (inst->used_##name) { PRINT_SEP(); strcat(inst->str, registers[inst->name]); } } while (0)

// Append an immediate field as hex (if it is marked as used)
#define PRINT_IMMEDIATE(name) do { if (inst->used_##name) { PRINT_SEP(); sprintf(inst->str, "%s#%X", inst->str, inst->name); } } while (0)

