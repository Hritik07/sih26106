/**
 * validate(schema)
 *
 * Minimal request-body validator so routes don't hand-roll `if (!x) return 400`
 * blocks. Schema shape:
 *   { field: { required: true, type: 'string' } }
 *
 * Deliberately dependency-free for the hackathon build; swap in Joi/Zod later
 * without touching route code if validation needs grow (nested objects,
 * enums with custom messages, etc.) — routes only ever call validate(schema).
 */
function validate(schema) {
  return (req, res, next) => {
    const errors = [];

    for (const [field, rules] of Object.entries(schema)) {
      const value = req.body[field];

      if (rules.required && (value === undefined || value === null || value === '')) {
        errors.push(`${field} is required`);
        continue;
      }
      if (value === undefined || value === null) continue; // optional & absent, skip type check

      if (rules.type && typeof value !== rules.type) {
        errors.push(`${field} must be of type ${rules.type}`);
      }
      if (rules.enum && !rules.enum.includes(value)) {
        errors.push(`${field} must be one of: ${rules.enum.join(', ')}`);
      }
    }

    if (errors.length) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', message: errors.join('; ') });
    }
    return next();
  };
}

module.exports = { validate };