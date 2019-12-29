const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

// Returns user model
const User = require('../../models/User');

// @route    POST api/users
// @desc     Register user
// @access   Public
router.post('/', [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
],
    async (req, res) => {
        const errors = validationResult(req);

        // If have errors
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, password } = req.body;

        try {
            // Find user by email in DB
            let user = await User.findOne({ email });

            // See if user already exists
            if (user) {
                return res.status(400).json({ errors: [{ msg: 'User already exists' }] });
            }

            // Get user gravatar
            const avatar = gravatar.url(email, {
                s: '200',
                r: 'pg',
                d: 'mm'
            })

            user = new User({
                name,
                email,
                avatar,
                password
            })

            // Ecrypt password
            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(password, salt);

            // Save user to DB
            await user.save();

            // Return jsonwebtoken
            const payload = {
                user: {
                    id: user.id
                }
            }

            jwt.sign(
                payload,
                config.get('jwtSecret'),
                { expiresIn: 360000000 },
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