#include <iostream>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <thread>
#include <chrono>
#include <termios.h>
#include <unistd.h>
#include <sys/select.h>

#define MAXX 32
#define MAXY 22
#define DIFFICULTY_PERCENTAGE 100

class SnakeGame {
private:
    struct termios old_tio, new_tio;
    std::vector<std::vector<int>> grid;
    int score;
    
public:
    SnakeGame();
    ~SnakeGame();
    void Initialize();
    void Game();
    void UpdateScreen();
    void DisplayScore();
    void Framing();
    void ClearScreen();
    bool KbHit();
    char GetChar();
    void GotoXY(int x, int y);
};

int main()
{
    SnakeGame game;
    game.Initialize();
    game.Game();
    return 0;
}

SnakeGame::SnakeGame() : grid(MAXY, std::vector<int>(MAXX, 0)), score(1) {
    // Save old terminal settings
    tcgetattr(STDIN_FILENO, &old_tio);
}

SnakeGame::~SnakeGame() {
    // Restore old terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);
    std::cout << "\033[?25h"; // Show cursor
    ClearScreen();
    std::cout << "\nGame Over! Final Score: " << score << std::endl;
}

void SnakeGame::Initialize()
{
    // Setup terminal for non-blocking input
    tcgetattr(STDIN_FILENO, &old_tio);
    new_tio = old_tio;
    new_tio.c_lflag &= (~ICANON & ~ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
    
    std::srand(std::time(nullptr));
    ClearScreen();
    
    std::cout << "\033[92m";
    std::cout << "  ╔═══════════════════════════════════╗\n";
    std::cout << "  ║           🐍 SNAKE GAME 🐍        ║\n";
    std::cout << "  ╚═══════════════════════════════════╝\n";
    std::cout << "\033[0m\n";
    std::cout << "\033[96mControls:\033[0m\n";
    std::cout << "  \033[93mW\033[0m - Move Up\n";
    std::cout << "  \033[93mA\033[0m - Move Left\n";
    std::cout << "  \033[93mS\033[0m - Move Down\n";
    std::cout << "  \033[93mD\033[0m - Move Right\n";
    std::cout << "  \033[91mESC\033[0m - Quit Game\n\n";
    std::cout << "\033[94mPress any key to start...\033[0m\n";
    
    char ch;
    read(STDIN_FILENO, &ch, 1);
    
    ClearScreen();
}

void SnakeGame::ClearScreen() {
    std::cout << "\033[2J\033[H\033[?25l"; // Clear screen, go to home, hide cursor
}

void SnakeGame::GotoXY(int x, int y) {
    std::cout << "\033[" << y << ";" << x << "H";
}

bool SnakeGame::KbHit() {
    char ch;
    
    if (read(STDIN_FILENO, &ch, 1) == 1) {
        return true;
    }
    return false;
}

char SnakeGame::GetChar() {
    char ch;
    read(STDIN_FILENO, &ch, 1);
    return ch;
}

void SnakeGame::Framing()
{
    GotoXY(1, 1);
    std::cout << "\033[95m"; // Magenta color for frame
    for(int i = 0; i < MAXX + 2; i++) std::cout << "#";
    std::cout << "\033[0m" << std::endl;
    
    for(int j = 0; j < MAXY; j++) {
        std::cout << "\033[95m#\033[0m";
        for(int i = 0; i < MAXX; i++) {
            std::cout << " ";
        }
        std::cout << "\033[95m#\033[0m" << std::endl;
    }
    
    std::cout << "\033[95m";
    for(int i = 0; i < MAXX + 2; i++) std::cout << "#";
    std::cout << "\033[0m" << std::endl;
    
    DisplayScore();
}


void SnakeGame::Game()
{
    enum dir
    {
        left = 'a', up = 'w', right = 'd', down = 's'
    };
    
    int foodx, foody, size = 1, headx, heady;
    char in = up, prev;
    
    // Initialize grid
    for(int i = 0; i < MAXX; i++) {
        for(int j = 0; j < MAXY; j++) {
            grid[j][i] = 0;
        }
    }
    
    // Random positions
    headx = MAXX / 2;  // Start in center
    heady = MAXY / 2;
    grid[heady][headx] = 1;
    
    // Place food away from snake
    do {
        foodx = std::rand() % MAXX;
        foody = std::rand() % MAXY;
    } while(foodx == headx && foody == heady);
    
    Framing(); // Draw initial frame
    
    while(in != 27) { // ESC key
        // Check for keyboard input
        fd_set readfds;
        struct timeval timeout;
        
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000; // 10ms timeout for more responsive input
        
        if(select(STDIN_FILENO + 1, &readfds, nullptr, nullptr, &timeout) > 0) {
            if(FD_ISSET(STDIN_FILENO, &readfds)) {
                char newInput = GetChar();
                // Only update if it's a valid direction key
                if(newInput == 'w' || newInput == 'a' || newInput == 's' || newInput == 'd' || newInput == 27) {
                    in = newInput;
                }
            }
        }
        
    Again:
        if((in == left && prev == right) || (in == up && prev == down) ||
           (in == down && prev == up) || (in == right && prev == left)) {
            in = prev;
        }
        
        switch(in) {
            case left:
                if(headx == 0) {
                    if(grid[heady][MAXX-1] != 0) in = 27;
                    else headx = MAXX - 1;
                } else if(grid[heady][--headx] != 0) in = 27;
                break;
            case right:
                if(headx == MAXX - 1) {
                    if(grid[heady][0] != 0) in = 27;
                    else headx = 0;
                } else if(grid[heady][++headx] != 0) in = 27;
                break;
            case up:
                if(heady == 0) {
                    if(grid[MAXY-1][headx] != 0) in = 27;
                    else heady = MAXY - 1;
                } else if(grid[--heady][headx] != 0) in = 27;
                break;
            case down:
                if(heady == MAXY - 1) {
                    if(grid[0][headx] != 0) in = 27;
                    else heady = 0;
                } else if(grid[++heady][headx] != 0) in = 27;
                break;
            case 27:
                break;
            default:
                in = prev;
                goto Again;
        }
        
        prev = in;
        grid[heady][headx] = size + 1;
        
        // Check if food is eaten
        if(headx == foodx && heady == foody) {
            do {
                foodx = std::rand() % MAXX;
                foody = std::rand() % MAXY;
            } while(grid[foody][foodx] != 0);
            
            size++;
            score = size;
            DisplayScore();
        }
        
        // Update and display grid
        for(int j = 0; j < MAXY; j++) {
            for(int i = 0; i < MAXX; i++) {
                GotoXY(i + 2, j + 2); // Offset for frame
                
                char displayChar = ' '; // Default to empty space
                std::string colorCode = "\033[0m"; // Reset color
                
                // Check if this position has food
                if(j == foody && i == foodx) {
                    displayChar = '*'; // Food
                    colorCode = "\033[91m"; // Bright red
                }
                // Check if this position has snake
                else if(grid[j][i] > 0) {
                    if(i == headx && j == heady) {
                        displayChar = '@'; // Snake head
                        colorCode = "\033[93m"; // Bright yellow
                    } else {
                        displayChar = 'O'; // Snake body
                        colorCode = "\033[92m"; // Bright green
                    }
                }
                
                std::cout << colorCode << displayChar << "\033[0m"; // Reset color after each character
            }
        }
        
        // Now decrement all grid values for next iteration
        for(int j = 0; j < MAXY; j++) {
            for(int i = 0; i < MAXX; i++) {
                if(grid[j][i] > 0) {
                    grid[j][i]--;
                }
            }
        }
        
        std::cout.flush();
        
        // Game speed control - make it more playable
        std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Fixed 200ms delay
    }
    
    // Wait for ESC to exit
    char ch;
    do {
        read(STDIN_FILENO, &ch, 1);
    } while(ch != 27);
}

void SnakeGame::UpdateScreen() {
    // Find and draw snake head (highest value in grid)
    int maxVal = 0;
    for(int j = 0; j < MAXY; j++) {
        for(int i = 0; i < MAXX; i++) {
            if(grid[j][i] > maxVal) {
                maxVal = grid[j][i];
            }
        }
    }
    
    for(int j = 0; j < MAXY; j++) {
        for(int i = 0; i < MAXX; i++) {
            GotoXY(i + 2, j + 2); // Offset for frame
            
            if(grid[j][i] > 0) {
                grid[j][i]--;
                if(grid[j][i] == maxVal - 1) {
                    std::cout << "@"; // Snake head
                } else if(grid[j][i] > 0) {
                    std::cout << "O"; // Snake body
                } else {
                    std::cout << " "; // Empty space
                }
            } else {
                std::cout << " "; // Empty space
            }
        }
    }
    
    std::cout.flush();
}

void SnakeGame::DisplayScore() {
    GotoXY(1, MAXY + 3);
    std::cout << "\033[96mScore: \033[93m" << score << "\033[0m  \033[94mUse WASD to move, ESC to quit\033[0m";
}
