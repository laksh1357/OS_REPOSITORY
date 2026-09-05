# Contributing to Warden Platform

Thank you for your interest in contributing to Warden! We welcome community pull requests, bug fixes, seccomp profile optimizations, and feature enhancements.

## Development Workflow

1. **Fork and Clone the Repository**
   ```bash
   git clone https://github.com/laksh1357/OS_REPOSITORY.git
   cd OS_REPOSITORY
   ```

2. **Start PostgreSQL Database**
   ```bash
   docker-compose up -d
   ```

3. **Install Dependencies & Start Dev Server**
   ```bash
   npm install
   npm run dev
   ```

4. **Run Test Suite**
   ```bash
   npm test
   ```

5. **Submitting a Pull Request**
   - Create a feature branch: `git checkout -b feature/my-new-feature`
   - Commit your changes with descriptive messages.
   - Push to your fork and submit a PR to `main`.
