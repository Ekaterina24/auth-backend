export default () => ({
    jwt: {
        secret: process.env.JWT_SECRET
    },
    database: {
        connectionString: process.env.MONGO_URL || 'mongodb+srv://katrykova1:Fizika852@cluster0.w4nct.mongodb.net?retryWrites=true&w=majority'
    }
})