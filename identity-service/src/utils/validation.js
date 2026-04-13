const Joi = require('joi');
// validate the schema based on the data
const validateRegistration = (data)=>{
    const schema = Joi.object({
        username : Joi.string().min(3).max(50).required(),
        email : Joi.string().email().required(),
        password : Joi.string().min(6).required()

    })

    return schema.validate(data)

}
const validatelogin = (data)=>{
    const schema = Joi.object({
        email : Joi.string().email().required(),
        password : Joi.string().min(6).required()

    })

    return schema.validate(data)

}

module.exports = {validateRegistration,validatelogin}