function errorHandler(err, req, res, next) {
    if (typeof err === 'string') {
        // Custom application error
        const is404 = err.toLowerCase().includes('not found');
        const statusCode = is404 ? 404 : 400;
        return res.status(statusCode).json({ message: err });
    }

    if (err.name === 'UnauthorizedError') {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    // Default 500
    console.error('[Server Error]', err);
    return res.status(500).json({ message: err.message || 'Internal Server Error' });
}

module.exports = errorHandler;
