
const RefreshToken = require('../models/RefreshToken');
const User = require('../models/User');
const generateTokens = require('../utils/generateToken');
const logger = require('../utils/logger')
const { validateRegistration, validatelogin } = require('../utils/validation')

// user registration
const registerUser = async(req,res)=>{
    logger.info('Registration endpoint hit')
    try {
        // validate the schema
        const {error} = validateRegistration(req.body);
        if(error){
            logger.warn('Validation Error',error.details[0].message)
            return res.status(400).json({
                success : false,
                message : error.details[0].message
            })
        }

        const {email,password,username} = req.body
        let user = await User.findOne({$or: [{email}, {username}]});
        if(user){
            logger.warn('User already Registered');
            return res.status(400).json({
                success : false,
                message : "User already exists"
            })

        }
        user = new User({username,email,password})
        await user.save()
        logger.info('User saved successfully',user._id);

        const {accessToken,refreshToken} = await generateTokens(user)
        res.status(201).json({
            success : true,
            message : 'user registered successfully',
            accessToken,
            refreshToken
        })
        

        
    } catch (error) {
        logger.error('Registration error occured',error)
        res.status(500).json({
            success : false,
            message : "Internal Server error"
        })
        
        
    }

}



// user login
const loginUser = async(req,res)=>{
    logger.info('Login End Point hit')
    try {
        const {error} = validatelogin(req.body)
        if(error){
            logger.warn('Validation Error',error.details[0].message)
            return res.status(400).json({
                success : false,
                message : error.details[0].message
            })
        }
        const {email,password} = req.body;
        const user = await User.findOne({email})
        if(!user){
            logger.warn('Invalid user')
            return res.status(400).json({
                success : false,
                message : 'Invalid Credentials'
            })
        }

        // valdi password or not
        const isValidPassword = await user.comparePassword(password)
        if(!isValidPassword){
            logger.warn('Invalid password')
            return res.status(400).json({
                success : false,
                message : 'Invalid password'
            })
        }

        const {accessToken,refreshToken} = await generateTokens(user)
        res.json({
            accessToken,
            refreshToken,
            userId : user._id
        })


        
    } catch (error) {
        logger.error('Registration error occured',error)
        res.status(500).json({
            success : false,
            message : "Internal Server error"
        })
        
    }
}



// user refresh token

const refreshTokenUser = async(req,res)=>{
    logger.info('Refresh Token Endpoint hit...')
    try {
        const {refreshToken} = req.body;
        if(!refreshToken){
            logger.warn('Refresh Token is missing')
            return res.status(400).json({
            success : false,
            message : "Refresh Token is missing"
        })
            
        }

        const storedToken = await RefreshToken.findOne({token : refreshToken})

        if(!storedToken || storedToken.expiresAt < new Date()){
            logger.warn('Invalid or Expired Refresh Token')
            return res.status(401).json({
                success : false,
                message : `Invalid or Expired Refresh Token`
            })
        }

        const user = await User.findById(storedToken.user)
        if(!user){
            logger.warn('User not found');
            return res.status(401).json({
                success : false,
                message : `User not found`
            })

        }
        const {accessToken : newAccessToken , refreshToken : newRefreshToken} = await generateTokens(user);

        // delete the old refresh token
        await RefreshToken.deleteOne({_id : storedToken._id})

        res.json({
            accessToken : newAccessToken,
            refreshToken : newRefreshToken
        })
        
        
    } catch (error) {
        logger.error('Refresh Token error occured',error)
        res.status(500).json({
            success : false,
            message : "Internal Server error"
        })
        
    }
}



// logout

const logoutUser = async(req,res)=>{
    logger.info('Logout Enfpoint hit')
    try {
        const {refreshToken} = req.body
        if(!refreshToken){
            logger.warn('Refesh token is missing')
            return res.status(400).json({
                success : false,
                message : 'Refresh Token missing'
            })
        }

        await RefreshToken.deleteOne({token : refreshToken})
        logger.info('Refresh token deleted for logout')
        res.json({
            success : true,
            message : 'Logged out Successfully'
        })
        
    } catch (error) {
        logger.error('Logout error occurred',error)
        res.status(500).json({
            success : false,
            message : "Internal Server error"
        })
        
    }
}

module.exports = {registerUser,loginUser,refreshTokenUser,logoutUser};