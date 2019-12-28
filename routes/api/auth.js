const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const auth = require('../../middleware/auth');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

const User = require('../../models/User');

// @route    GET api/auth
// @desc     Test route
// @access   Public
router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }
});


// @route    POST api/auth
// @desc     Authenticate user & get token
// @access   Public
router.post('/',
    [
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Password is required').exists()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        // If have errors
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        try {
            // Find user by email in DB
            let user = await User.findOne({ email });

            // See if user already exists
            if (!user) {
                return res.status(400).json({ errors: [{ msg: 'Invalid Email' }] });
            }

            const isMatch = await bcrypt.compare(password, user.password);

            if (!isMatch) {
                return res.status(400).json({ errors: [{ msg: 'Invalid Password' }] });
            }

            // Return jsonwebtoken
            const payload = {
                user: {
                    id: user.id
                }
            }

            jwt.sign(
                payload,
                config.get('jwtSecret'),
                { expiresIn: 360000 },
                (error, token) => {
                    if (error) throw error;
                    res.json({ token });
                }
            );

        } catch (error) {
            console.error(error.message);
            res.status(500).send('Server error');
        }


    });

module.exports = router;