#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <capstone/capstone.h>
#include <errno.h>

#include "./ptrace_utils.h"

#define INT3 0xcc
#define N_INS_PEEK 5

uint8_t *text = NULL;
uint64_t text_size = 0;
uint64_t offset = 0;
csh handle;

static Elf64_Shdr get_section_hdr64(FILE *file_ptr, Elf64_Ehdr elf_hdr, Elf64_Off n)
{
  Elf64_Shdr section_hdr;
  fseeko(file_ptr, elf_hdr.e_shoff + n * elf_hdr.e_shentsize, SEEK_SET);
  fread(&section_hdr, sizeof(section_hdr), 1, file_ptr);
  return section_hdr;
}

static void get_text_section(const char *path, uint8_t **textptr, uint64_t *n, uint64_t *sh_addr)
{
  FILE *file_ptr = fopen(path, "rb");

  unsigned char e_ident[EI_NIDENT];
  fread(e_ident, 1, EI_NIDENT, file_ptr);
  if (strncmp((char *)e_ident, "\x7f"
                               "ELF",
              4) != 0)
  {
    printf("ELFMAGIC mismatch!\n");
    fclose(file_ptr);
    return;
  }

  if (e_ident[EI_CLASS] == ELFCLASS64)
  {
    Elf64_Ehdr elf_hdr;
    memcpy(elf_hdr.e_ident, e_ident, EI_NIDENT);
    fread((void *)&elf_hdr + EI_NIDENT, sizeof(elf_hdr) - EI_NIDENT, 1, file_ptr);

    Elf64_Off shstrndx;
    if (elf_hdr.e_shstrndx == SHN_XINDEX)
    {
      shstrndx = get_section_hdr64(file_ptr, elf_hdr, 0).sh_link;
    }
    else
    {
      shstrndx = elf_hdr.e_shstrndx;
    }

    Elf64_Shdr section_hdr_string_tbl_hdr = get_section_hdr64(file_ptr, elf_hdr, shstrndx);
    char *const section_hdr_string_tbl = malloc(section_hdr_string_tbl_hdr.sh_size);
    fseeko(file_ptr, section_hdr_string_tbl_hdr.sh_offset, SEEK_SET);
    fread(section_hdr_string_tbl, 1, section_hdr_string_tbl_hdr.sh_size, file_ptr);

    Elf64_Off shnum;
    if (elf_hdr.e_shnum == SHN_UNDEF)
    {
      shnum = get_section_hdr64(file_ptr, elf_hdr, 0).sh_size;
    }
    else
    {
      shnum = elf_hdr.e_shnum;
    }

    for (Elf64_Off i = 0; i < shnum; i++)
    {
      Elf64_Shdr section_hdr = get_section_hdr64(file_ptr, elf_hdr, i);
      // we are only interested in .text section
      if (strcmp(".text", section_hdr_string_tbl + section_hdr.sh_name) == 0)
      {
        *textptr = malloc(section_hdr.sh_size);
        fseeko(file_ptr, section_hdr.sh_offset, SEEK_SET);
        fread(*textptr, 1, section_hdr.sh_size, file_ptr);
        *n = section_hdr.sh_size;
        *sh_addr = section_hdr.sh_addr;
        break;
      }
    }
    free(section_hdr_string_tbl);
  }
  fclose(file_ptr);
}

static void disassemble(uint64_t rip)
{
  cs_insn *insn;
  size_t count = cs_disasm(handle, &text[rip - offset], text_size - (rip - offset), rip, N_INS_PEEK, &insn);
  for (size_t i = 0; i < count; i++)
  {
    char bytes[128] = "";
    for (int j = 0; j < insn[i].size; j++)
    {
      snprintf(&bytes[j * 3], 4, "%2.2x ", insn[i].bytes[j]);
    }
    printf("\t%" PRIx64 ": %-32s%s\t%s\n", insn[i].address, bytes, insn[i].mnemonic, insn[i].op_str);
  }
  cs_free(insn, count);
  if (count < N_INS_PEEK)
  {
    printf("** the address is out of the range of the text section.\n");
  }
}

pid_t load(char *argv[])
{
  struct user_regs_struct regs;
  pid_t tracee = fork();
  if (tracee == -1)
  {
    perror("fork()");
  }

  if (tracee == 0)
  {
    ptrace_traceme();
    execvp(argv[1], argv + 1);
    perror("execvp()");
    exit(1);
  }

  int tracee_status;
  waitpid(tracee, &tracee_status, 0);
  if (WIFEXITED(tracee_status))
    return -1;

  get_text_section(argv[1], &text, &text_size, &offset);

  ptrace_getregs(tracee, &regs);
  printf("** program '%s' loaded. entry point %p\n", argv[1], (void *)regs.rip);
  disassemble(regs.rip);
  return tracee;
}

int main(int _argc, char *_argv[])
{
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
  {
    return -1;
  }
  char *argv[100] = {0};

  pid_t tracee = -1;
  int tracee_status;
  struct user_regs_struct regs;

  if (_argc > 1)
  {
    memcpy(argv, _argv, _argc * sizeof(char *));
    tracee = load(argv);
  }

  uint64_t breaks[100] = {0};
  int n_breaks = 0;

  char *line = NULL;
  size_t line_size = 0;

  for (;;)
  {
    printf("(sdb) ");
    if (getline(&line, &line_size, stdin) == -1)
      return 0;

    argv[0] = line;
    for (int i = 0; i < 99 && argv[i]; ++i)
    {
      argv[i] = __strtok_r(argv[i], " \n\r", &argv[i + 1]);
    }

    if (!argv[0])
      continue;

    if (!strcmp(argv[0], "load"))
    {
      tracee = load(argv);
      continue;
    }

    if (tracee == -1)
    {
      puts("** please load a program first.");
      continue;
    }

    if (!strcmp(argv[0], "break"))
    {
      if (!argv[1])
        continue;
      errno = 0;
      uint64_t addr = strtoull(argv[1], NULL, 16);
      if (errno)
        continue;

      breaks[n_breaks++] = addr;
      long data = ptrace_peektext(tracee, addr);
      ((uint8_t *)&data)[0] = INT3;
      ptrace_poketext(tracee, addr, data);
      printf("** set a breakpoint at %p.\n", (void *)addr);
      continue;
    }

    if (!strcmp(argv[0], "delete"))
    {
      if (!argv[1])
        continue;
      errno = 0;
      int break_num = strtoull(argv[1], NULL, 10);
      if (errno)
        continue;

      if (breaks[break_num])
      {
        printf("** delete breakpoint %d.\n", break_num);
        long data = ptrace_peektext(tracee, breaks[break_num]);
        ((uint8_t *)&data)[0] = text[breaks[break_num] - offset];
        ptrace_poketext(tracee, breaks[break_num], data);
        breaks[break_num] = 0;
      }
      else
      {
        printf("** breakpoint %d does not exist.\n", break_num);
      }

      continue;
    }

    if (!strcmp(argv[0], "info"))
    {
      if (!argv[1])
        continue;
      if (!strcmp(argv[1], "break"))
      {
        bool flag = false;
        for (int i = 0; i < n_breaks; ++i)
          if (breaks[i])
          {
            flag = true;
            break;
          }

        if (!flag)
        {
          puts("** no breakpoints.");
          continue;
        }
        printf("%-10s %-10s\n", "Num", "Address");
        for (int i = 0; i < n_breaks; ++i)
          if (breaks[i])
            printf("%-10d %-10p\n", i, (void *)breaks[i]);

        continue;
      }
      continue;
    }

    if (!strcmp(argv[0], "si"))
    {
      ptrace_getregs(tracee, &regs);
      long next_ins = ptrace_peektext(tracee, regs.rip);
      if (((uint8_t *)&next_ins)[0] == INT3)
      {
        ((uint8_t *)&next_ins)[0] = text[regs.rip - offset];
        ptrace_poketext(tracee, regs.rip, next_ins);

        ptrace_setregs(tracee, &regs);
        ptrace_singlestep(tracee);
        waitpid(tracee, &tracee_status, 0);
        if (WIFEXITED(tracee_status))
          break;

        ((uint8_t *)&next_ins)[0] = INT3;
        ptrace_poketext(tracee, regs.rip, next_ins);
      }
      else
      {
        ptrace_singlestep(tracee);
        waitpid(tracee, &tracee_status, 0);
        if (WIFEXITED(tracee_status))
          break;
      }

      ptrace_getregs(tracee, &regs);

      next_ins = ptrace_peektext(tracee, regs.rip);
      if (((uint8_t *)&next_ins)[0] == INT3)
        printf("** hit a breakpoint %p.\n", (void *)regs.rip);

      disassemble(regs.rip);
      continue;
    }

    if (!strcmp(argv[0], "cont"))
    {
      ptrace_getregs(tracee, &regs);
      long next_ins = ptrace_peektext(tracee, regs.rip);
      if (((uint8_t *)&next_ins)[0] == INT3)
      {
        ((uint8_t *)&next_ins)[0] = text[regs.rip - offset];
        ptrace_poketext(tracee, regs.rip, next_ins);

        ptrace_setregs(tracee, &regs);
        ptrace_singlestep(tracee);
        waitpid(tracee, &tracee_status, 0);
        if (WIFEXITED(tracee_status))
          break;

        ((uint8_t *)&next_ins)[0] = INT3;
        ptrace_poketext(tracee, regs.rip, next_ins);
      }
      ptrace_cont(tracee);
      waitpid(tracee, &tracee_status, 0);
      if (WIFEXITED(tracee_status))
        break;

      ptrace_getregs(tracee, &regs);
      --regs.rip;
      ptrace_setregs(tracee, &regs);
      printf("** hit a breakpoint %p.\n", (void *)regs.rip);
      disassemble(regs.rip);
      continue;
    }

    if (!strcmp(argv[0], "jmp"))
    {
      if (!argv[1])
        continue;
      errno = 0;
      uint64_t rip = strtoull(argv[1], NULL, 16);
      if (errno)
        continue;
      ptrace_getregs(tracee, &regs);
      regs.rip = rip;
      ptrace_setregs(tracee, &regs);
      printf("** jump to %p.\n", (void *)rip);
      disassemble(rip);
      continue;
    }

    if (!strcmp(argv[0], "disasm"))
    {
      ptrace_getregs(tracee, &regs);
      disassemble(regs.rip);
      continue;
    }

    printf("** unknown command [%s].\n", argv[0]);
  }
  puts("** the target program terminated.");

  return 0;
}