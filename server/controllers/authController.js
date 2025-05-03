const User = require("../models/User")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")

exports.register = async (res, req) => {
    // get user data form req body
    const { name, email, password } = req.body;
    //validation 
    if (!name || !email || !password) {
        return res.status(400).json({
            message: "all fields are required"
        })
    }
    try {
        //check if user already registered
        const userExists = await User.findOne({ email });
        //if user present then return response
        if (userExists) {
            return res.status(400).json({
                success: false,
                message: "User already exists"
            })
        }
        // if not then hash the password and make user entry in db 
        const hashedPass = await bcrypt.hash(password, 10)
        const user = await User.create({
            name,
            email,
            password: hashedPass,
            role: "User"
        })

        //create jwt token

        const token = jwt.sign(
            {
                id: user._id,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        )

        // return response 
        return res.status(200).json({
            success: true,
            message: "user registered successfully",
            user: { id: user._id, name: user.name, email: user.email },
            token
        })

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "something went wrong please try again"
        })
    }
}

exports.login = async (req, res) => {
    const { email, password } = req.body;

    //validation 
    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: "both email and password are required"
        })
    }
    try {
        // check if user exists or not 
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "user does not exists"
            })
        }

        // check pass is correct or not 
        const isMatch = await bcrypt.compare(password.user.password);
        if (!isMatch) return res.status(401).json({ message: "password is incorrect please enter the valid password" })

        const token = jwt.sign(
            { id: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        //return res
        return res.status(200).json({
            user: { id: user._id, name: user.name, email: user.email },
            token
        })

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "something went wrong"
        })
    }
}