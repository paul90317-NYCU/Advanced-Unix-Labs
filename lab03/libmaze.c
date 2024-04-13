#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>

#include "libmaze.h"
#include "elf.h"

typedef void (*move_func_t)(maze_t *);
typedef maze_t *(*maze_load_t)(const char *);
typedef void *(*maze_get_ptr_t)();

size_t pagesize;

int move_list[1200];
move_func_t move_dirs[4];
void *main_handle = NULL;

void preassign_got(int i){
	move_func_t *got_entry = maze_get_ptr() + elf_moves[i];
	void *get_entry_page = (void *)((size_t) got_entry & ~(pagesize - 1));
	if(mprotect(get_entry_page, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
		perror("mprotect");
	*got_entry = move_dirs[move_list[i]];
}

int
maze_init() {
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
		void *get_entry_page = (void *)((size_t) move_dirs[i] & ~(pagesize - 1));
		if(mprotect(get_entry_page, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
			perror("mprotect");
	}
	dlclose(main_handle);
	return 0;
}

void DFS(maze_t *mz);

maze_t *
maze_load(const char *fn) {
	maze_t *mz = NULL;
	FILE *fp = NULL;
	int i, j, k;
	//
	if((fp = fopen(fn, "rt")) == NULL) {
		fprintf(stderr, "MAZE: fopen failed - %s.\n", strerror(errno));
		return NULL;
	}
	if((mz = (maze_t*) malloc(sizeof(maze_t))) == NULL) {
		fprintf(stderr, "MAZE: alloc failed - %s.\n", strerror(errno));
		goto err_quit;
	}
	if(fscanf(fp, "%d %d %d %d %d %d", &mz->w, &mz->h, &mz->sx, &mz->sy, &mz->ex, &mz->ey) != 6) {
		fprintf(stderr, "MAZE: load dimensions failed - %s.\n", strerror(errno));
		goto err_quit;
	}
	mz->cx = mz->sx;
	mz->cy = mz->sy;
	for(i = 0; i < mz->h; i++) {
		for(j = 0; j < mz->w; j++) {
			if(fscanf(fp, "%d", &k) != 1) {
				fprintf(stderr, "MAZE: load blk (%d, %d) failed - %s.\n", j, i, strerror(errno));
				goto err_quit;
			}
			mz->blk[i][j] = k<<20;
		}
	}
	fclose(fp);
	fprintf(stderr, "MAZE: loaded [%d, %d]: (%d, %d) -> (%d, %d)\n",
		mz->w, mz->h, mz->sx, mz->sy, mz->ex, mz->ey);
	DFS(mz);
	return mz;
err_quit:
	if(mz) free(mz);
	if(fp) fclose(fp);
	return NULL;
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
		preassign_got(i);
	}
}
