const express = require('express');
const fs = require('fs');
const app = express();
const port = process.env.PORT || 3000;
const db = require('./db');
const { GoogleGenerativeAI } = require("@google/generative-ai");

app.use(express.json());

// Serve static files from the client folder
app.use(express.static('client'));

// Load FAQ data
const faqData = JSON.parse(fs.readFileSync('./server/faq.json', 'utf-8'));

// In-memory conversation state (for simplicity, not suitable for production)
const conversationState = {};

// Access your API key as an environment variable
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

async function run(prompt) {
  const model = genAI.getGenerativeModel({ model: "gemini-pro"});
  const result = await model.generateContent(prompt);
  const response = await result.response;
  const text = response.text();
  return text;
}

function isDbConnected() {
  return db && db.state !== 'disconnected';
}

// API endpoint for chatbot messages
app.post('/api/chat', async (req, res) => {
  const userMessage = req.body.message;
  const userId = 'default-user'; // In a real app, you'd have user sessions

  // Check for FAQ
  const faqMatch = faqData.find(item => userMessage.toLowerCase().includes(item.question.toLowerCase()));
  if (faqMatch) {
    const botResponse = faqMatch.answer;
    return res.json({ response: botResponse });
  }

  // Data capture logic
  if (userMessage.toLowerCase().includes('register')) {
    conversationState[userId] = { step: 'getName' };
    const botResponse = "Great! What's your name?";
    return res.json({ response: botResponse });
  }

  if (conversationState[userId]) {
    const state = conversationState[userId];
    let botResponse = '';

    if (state.step === 'getName') {
      state.name = userMessage;
      state.step = 'getEmail';
      botResponse = `Thanks, ${state.name}! What's your email?`;
    } else if (state.step === 'getEmail') {
      state.email = userMessage;
      state.step = 'getPhone';
      botResponse = "Got it. What's your phone number?";
    } else if (state.step === 'getPhone') {
      state.phone = userMessage;

      if (isDbConnected()) {
        // Save to database
        const query = 'INSERT INTO users (name, email, phone) VALUES (?, ?, ?)';
        db.query(query, [state.name, state.email, state.phone], (err, result) => {
          if (err) {
            console.error('Error saving user to database:', err);
            botResponse = 'Sorry, there was an error saving your information.';
          } else {
            botResponse = 'Thanks for registering! Your information has been saved.';
          }
          delete conversationState[userId]; // End conversation
          res.json({ response: botResponse });
        });
        return; // a bit different here because of the async db call
      } else {
        botResponse = "I can't save your information right now because the database is not connected. Please try again later.";
        delete conversationState[userId]; // End conversation
        return res.json({ response: botResponse });
      }
    }
    return res.json({ response: botResponse });
  }

  // Default to Gemini
  try {
    const botResponse = await run(userMessage);

    if (isDbConnected()) {
      // Save message to the database
      const query = 'INSERT INTO messages (user_message, bot_response) VALUES (?, ?)';
      db.query(query, [userMessage, botResponse], (err, result) => {
        if (err) {
          console.error('Error saving message to database:', err);
          // still send response to user
        }
      });
    }
    res.json({ response: botResponse });
  } catch (error) {
    console.error('Error with Gemini API:', error);
    res.status(500).json({ error: 'Error with Gemini API' });
  }
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
