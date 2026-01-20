# Contributing to SaaSReady

Thank you for your interest in contributing to SaaSReady! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful, inclusive, and constructive in all interactions.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/ramprag/saasready/issues)
2. If not, create a new issue with:
    - Clear title and description
    - Steps to reproduce
    - Expected vs actual behavior
    - Screenshots if applicable
    - Environment details (OS, Python version, etc.)

### Suggesting Features

1. Check existing [Issues](https://github.com/ramprag/saasready/issues) and [Discussions](https://github.com/ramprag/saasready/discussions)
2. Create a new discussion in the "Ideas" category
3. Describe the feature and its use case
4. Explain why it would be valuable

### Pull Requests

1. **Fork the repository**
```bash
   git clone https://github.com/ramprag/saasready.git
   cd saasready
```

2. **Create a feature branch**
```bash
   git checkout -b feature/your-feature-name
```

3. **Make your changes**
    - Follow existing code style
    - Add tests for new features
    - Update documentation as needed

4. **Test your changes**
```bash
   # Backend tests
   cd backend
   pytest -v
   
   # Frontend lint
   cd frontend
   npm run lint
```

5. **Commit with clear messages**
```bash
   git commit -m "Add feature: description of what you added"
```

6. **Push to your fork**
```bash
   git push origin feature/your-feature-name
```

7. **Create a Pull Request**
    - Go to the original repository
    - Click "New Pull Request"
    - Select your branch
    - Fill in the PR template

## Development Setup
```bash
# Clone repo
git clone https://github.com/ramprag/saasready.git
cd saasready

# Setup environment (docker-compose reads .env from root)
cp backend/.env.example .env
cp frontend/.env.local.example frontend/.env.local

# Start services
docker-compose up --build
```

## Coding Standards

### Python (Backend)
- Follow PEP 8
- Use type hints
- Write docstrings for functions
- Keep functions focused and small
- Use meaningful variable names

### TypeScript (Frontend)
- Use TypeScript strictly
- Follow React best practices
- Use functional components with hooks
- Keep components small and focused
- Use meaningful component and variable names

### Git Commits
- Use present tense ("Add feature" not "Added feature")
- Keep first line under 50 characters
- Reference issues when applicable



## 📜 Code of Conduct
## Our Pledge
We are committed to providing a welcoming and inclusive experience for everyone.
## Our Standards

Be respectful and inclusive
Accept constructive criticism
Focus on what's best for the community
Show empathy towards others

## 🚫 Unacceptable Behavior

Harassment or discriminatory language
Personal attacks
Trolling or insulting comments
Publishing private information

## Enforcement
Violations can be reported to support@saasready.com. All complaints will be reviewed and investigated.


## Questions?

Feel free to ask in [Discussions](https://github.com/ramprag/saasready/discussions) or open an issue.

Thank you for contributing to SaaSReady! 🎉