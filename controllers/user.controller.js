const User = require('../models/auth.model');

// Read user profile
exports.readController = async (req, res) => {
    try {
        const userId = req.params.id;
        const user = await User.findById(userId);

        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        user.hashed_password = undefined;
        user.salt = undefined;

        return res.json(user);
    } catch (err) {
        return res.status(500).json({ error: 'Server error' });
    }
};

// Update user profile
exports.updateController = async (req, res) => {
    try {
        const { name, password } = req.body;

        const user = await User.findById(req.user._id);

        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        if (!name) {
            return res.status(400).json({ error: 'Name is required' });
        }

        user.name = name;

        if (password) {
            if (password.length < 6) {
                return res.status(400).json({ error: 'Password should be at least 6 characters long' });
            }
            user.password = password;
        }

        const updatedUser = await user.save();

        updatedUser.hashed_password = undefined;
        updatedUser.salt = undefined;

        return res.json(updatedUser);
    } catch (err) {
        console.error('USER UPDATE ERROR', err);
        return res.status(500).json({ error: 'User update failed' });
    }
};
