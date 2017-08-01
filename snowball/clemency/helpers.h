// Macros and inline functions
static uint64_t read_54(inst_t *inst)
{
    uint64_t result;
    const uint16_t *ptr = inst->bytes + inst->size;
    result = ((uint64_t)ptr[1] << 45) | ((uint64_t)ptr[0] << 36) | ((uint64_t)ptr[2] << 27) | ((uint64_t)ptr[4] << 18) | (ptr[3] << 9) | (ptr[5] << 0);
    inst->size += 6;
    return result;
}

static uint64_t read_45(inst_t *inst)
{
    uint64_t result;
    const uint16_t *ptr = inst->bytes + inst->size;
    result = ((uint64_t)ptr[1] << 36) | ((uint64_t)ptr[0] << 27) | ((uint64_t)ptr[2] << 18) | (ptr[4] << 9) | (ptr[3] << 0);
    inst->size += 5;
    return result;
}

static uint64_t read_36(inst_t *inst)
{
    uint64_t result;
    const uint16_t *ptr = inst->bytes + inst->size;
    result = ((uint64_t)ptr[1] << 27) | ((uint64_t)ptr[0] << 18) | (ptr[2] << 9) | (ptr[3] << 0);
    inst->size += 4;
    return result;
}

static uint32_t read_27(inst_t *inst)
{
    uint32_t result;
    const uint16_t *ptr = inst->bytes + inst->size;
    result = ((uint64_t)ptr[1] << 18) | (ptr[0] << 9) | (ptr[2] << 0);
    inst->size += 3;
    return result;
}

static uint32_t read_18(inst_t *inst)
{
    uint32_t result;
    const uint16_t *ptr = inst->bytes + inst->size;
    result = (ptr[1] << 9) | (ptr[0] << 0);
    inst->size += 2;
    return result;
}

static uint16_t read_9(inst_t *inst)
{
    uint16_t result;
    const uint16_t *ptr = inst->bytes + inst->size;
    result = ptr[0];
    inst->size += 1;
    return result;
}

// Extract bits [offset, offset+count)
#define EXTRACT(src, offset, count) (((src) >> (bit_size - count - offset)) & ((1 << (count))-1))

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

