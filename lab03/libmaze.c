#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>

#include "libmaze.h"
#include "elf.h"

static void * __stored_ptr = NULL;

typedef void (*move_func_t)(maze_t *);
typedef maze_t *(*maze_load_t)(const char *);
typedef void *(*maze_get_ptr_t)();

size_t pagesize;

int move_list[1200];
move_func_t move_dirs[4];
maze_load_t maze_load_f;
void *main_handle = NULL;

void hijack(const void **GOT_entry, const void *func_ptr){
	void *GOT_entry_page = (void *)((__uint64_t) GOT_entry & ~(pagesize - 1));
	if(mprotect(GOT_entry_page, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
		perror("mprotect");
	*GOT_entry = func_ptr;
}

maze_t *my_maze_load(const char *fn);

int
maze_init() {
	fprintf(stderr, "UP112_GOT_MAZE_CHALLENGE\n");
	fprintf(stderr, "MAZE: library init - stored pointer = %p.\n", maze_get_ptr());
	pagesize = sysconf(_SC_PAGE_SIZE);
	main_handle = dlopen(NULL, RTLD_LAZY);
	if (!main_handle)
		perror(dlerror());
	char *move_dirs_name[] = {"move_up", "move_down", "move_left", "move_right"};
	for(int i = 0; i < 4; ++i) {
		move_dirs[i] = dlsym(main_handle, move_dirs_name[i]);
		if(!move_dirs[i])
			perror(dlerror());
	}
	maze_load_f = dlsym(main_handle, "maze_load");
	dlclose(main_handle);
	hijack(maze_get_ptr() + elf_maze_load, my_maze_load);
	return 0;
}

void DFS(maze_t *mz);

void
maze_set_ptr(void *ptr) {
	__stored_ptr = ptr;
}

void *
maze_get_ptr() {
	return __stored_ptr;
}

maze_t *
my_maze_load(const char *fn) {
	maze_t *mz = maze_load_f(fn);
	if(mz)
		DFS(mz);
	return mz;
}

void
maze_free(maze_t *mz) {
	free(mz);
}

static int _dirx[] = { 0, 0, -1, 1 };
static int _diry[] = { -1, 1, 0, 0 };

int move_list[1200];
int move_count;

// Depth-First Search 
int finded;
int move_count;
void dfs(maze_t *mz, int y, int x) {
    if (move_count == 1200)
        return;
    if(finded)
        return;
    if (x == mz->ex && y == mz->ey) {
        finded = 1;
        return;
    }
    if(mz->blk[y][x])
        return;

    move_count += 1;
    mz->blk[y][x] = 1;
    for (int i = 0; i < 4; i++) {
        int new_x = x + _dirx[i];
        int new_y = y + _diry[i];
        move_list[move_count - 1] = i;
        dfs(mz, new_y, new_x);
        if(finded){
			mz->blk[y][x] = 0;
			return;
		}
    }
    mz->blk[y][x] = 0;
    move_count -= 1;
    return;
}

void DFS(maze_t *mz){
	finded = 0;
    move_count = 0;
	dfs(mz, mz->sy, mz->sx);
	for(int i = 0; i < move_count; ++i){
		hijack(maze_get_ptr() + elf_moves[i],move_dirs[move_list[i]]);
	}
}
