# Snake Game - Modernized & Enhanced 🐍

This is a modernized and enhanced version of the classic Snake game, originally written for Borland Turbo C++, now updated to work with modern C++ standards and featuring improved graphics and gameplay.

## 🎮 Game Features

- **🐍 Colorful Snake**: Yellow head (@) and green body (O) for clear visibility
- **🍎 Red Food**: Bright red food items (*) that are easy to spot
- **🎨 Colorful UI**: Magenta borders and color-coded score display
- **⚡ Smooth Gameplay**: Optimized 200ms game loop for responsive controls
- **🎯 Smart Controls**: WASD movement with direction validation
- **📊 Real-time Score**: Live score updates with color highlighting
- **🖥️ Clean Display**: Hidden cursor and optimized screen rendering

## 🔧 Technical Improvements

### Fixed Display Issues
- ✅ **Snake Visibility**: Fixed rendering logic so snake and tail are always visible
- ✅ **Proper Tail Rendering**: Snake body segments now display correctly
- ✅ **Food Placement**: Food no longer overlaps with snake at start
- ✅ **Screen Management**: Better cursor positioning and screen clearing

### Enhanced Graphics
- 🎨 **ANSI Colors**: Full color support for better visual experience
- 🖱️ **Cursor Management**: Hidden cursor during gameplay for cleaner look
- 🎭 **Visual Feedback**: Color-coded game elements (snake, food, UI)
- 📺 **Better Layout**: Improved frame design with colored borders

### Improved Controls
- ⌨️ **Responsive Input**: 10ms input timeout for better responsiveness
- 🎮 **Input Validation**: Only accepts valid direction keys
- 🚫 **Direction Prevention**: Prevents 180-degree turns that cause instant death

## How to Compile and Run

```bash
g++ -std=c++11 -o snake SNAKE.CPP
./snake
```

## Controls
- **W** - Move Up
- **A** - Move Left  
- **S** - Move Down
- **D** - Move Right
- **ESC** - Quit Game

## Game Features
- Snake grows when eating food (*)
- Score increases with each food eaten
- Snake wraps around screen edges
- Game ends when snake collides with itself
- Real-time score display

## Technical Notes
- Game runs in terminal/console
- Uses ANSI escape sequences for graphics
- Requires POSIX-compliant system (macOS, Linux)
- For Windows, consider using Windows Subsystem for Linux (WSL)
