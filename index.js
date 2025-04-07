const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const {
    DynamoDBDocumentClient,
    GetCommand,
    PutCommand
} = require('@aws-sdk/lib-dynamodb');
require('dotenv').config();

const app = express();
app.use(express.json());

// Load env variables
const {
    JWT_SECRET,
    AWS_DYNAMODB_REGION,
    AWS_DYNAMODB_ACCESS_KEY,
    AWS_DYNAMODB_SECRET_KEY
} = process.env;

// Create DynamoDB v3 client
const client = new DynamoDBClient({
    region: AWS_DYNAMODB_REGION,
    credentials: {
        accessKeyId: AWS_DYNAMODB_ACCESS_KEY,
        secretAccessKey: AWS_DYNAMODB_SECRET_KEY
    }
});

// Create DynamoDB Document client (for easier use with JSON)
const dynamo = DynamoDBDocumentClient.from(client);

// 🔐 SIGNUP
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;

    try {
        const { Item } = await dynamo.send(new GetCommand({
            TableName: 'testusers',
            Key: { email }
        }));

        if (Item) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await dynamo.send(new PutCommand({
            TableName: 'testusers',
            Item: { email, password: hashedPassword }
        }));

        res.status(201).json({ message: 'User registered successfully' });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/', (req, res) => {
    res.send('✅ Auth API is running');
});

// 🔐 LOGIN
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const { Item } = await dynamo.send(new GetCommand({
            TableName: 'testusers',
            Key: { email }
        }));

        if (!Item) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, Item.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });

        res.json({ token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.listen(7000, () => console.log('🚀 Server running on port 7000'));
