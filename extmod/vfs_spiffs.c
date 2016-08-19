// Glue to SPIFFS written with reference to vfs_SPIFFS_file.c

#include "py/runtime.h"
#include "py/stream.h"
#include "spiffs.h"

extern const mp_obj_type_t spiffs_type_fileio;
extern const mp_obj_type_t spiffs_type_textio;

// A filesystem object
typedef struct {
    mp_obj_base_t base;
    struct spiffs_t fs;

} mp_obj_SPIFFS_vfs_t;

static mp_obj_SPIFFS_vfs_t fs;
u8_t spiffs_dbg_flag;

// Have this pointer as well just in case (can't arsed to work out how to get at it)

// An open file
typedef struct {
    mp_obj_base_t base;
    spiffs_file handle;

} SPIFFS_file_t;

#ifdef SIMULATE_FLASH
static u8_t simulated_flash[SPIFFS_CFG_PHYS_SZ()];
#else
#include <user_interface.h>
#include <spi_flash.h>
#include "ets_alt_task.h"
#define EIO 5
#endif

// The ESP interface requires 32 bit word aligned addresses

static s32_t my_spi_read(u32_t addr, u32_t size, u8_t *dst) {
	if (size >= 32) ets_loop_iter();
	if (spiffs_dbg_flag & 32) printf("my_spi_read(0x%x, %u, 0x%lx)\n", (unsigned) addr, (unsigned) size, (unsigned long) dst);
#ifdef SIMULATE_FLASH
	memcpy(dst, simulated_flash+addr-SPIFFS_CFG_PHYS_ADDR(), size);
	return SPIFFS_OK;
#else
	SpiFlashOpResult result;
	uint_fast8_t preamble = - (uint_fast8_t) dst & 3;

	u32_t size0 = size;

	if (preamble)
	{
		uint32 buffer = 0xaaaa;
		if (size < preamble) preamble = size;
		result = spi_flash_read(addr, &buffer, preamble);
		if (spiffs_dbg_flag & 32) printf("spi_flash_read(%x, data %x, %u)->%u\n", (unsigned) addr, (unsigned) buffer, (unsigned) preamble, result);
		if (result != SPI_FLASH_RESULT_OK) return result == SPI_FLASH_RESULT_TIMEOUT ? MP_ETIMEDOUT : MP_EIO;
		memcpy(dst, &buffer, preamble);
		dst  += preamble;
		addr += preamble;
		size -= preamble;
	}
	if (size >= 4)
	{
		u32_t body = size & ~3;
		result = spi_flash_read(addr, (uint32 *) dst, body);
		if (spiffs_dbg_flag & 32) printf("spi_flash_read(%x, %x, %u)->%u\n", (unsigned) addr, (unsigned) dst, (unsigned) body, result);
		if (result != SPI_FLASH_RESULT_OK) return result == SPI_FLASH_RESULT_TIMEOUT ? MP_ETIMEDOUT : MP_EIO;
		dst  += body;
		addr += body;
		size -= body;
	}
	if (size)
	{
		uint32 buffer = 0xaaaa;
		result = spi_flash_read(addr, &buffer, size);
		if (spiffs_dbg_flag & 32) printf("spi_flash_read(%x, data %x, %u)->%u\n", (unsigned) addr, (unsigned) buffer, (unsigned) size, result);
		if (result != SPI_FLASH_RESULT_OK) return result == SPI_FLASH_RESULT_TIMEOUT ? MP_ETIMEDOUT : MP_EIO;
		memcpy(dst, &buffer, size);
	}

	dst -= size0;
	if (spiffs_dbg_flag & 16) while (size0--) {if (!(size0 & 15)) ets_loop_iter();printf("%02x ", (unsigned) *dst++);}
	return SPIFFS_OK;
#endif
}

static s32_t my_spi_write(u32_t addr, u32_t size, u8_t *src) {
	if (size >= 32) ets_loop_iter();
	if (spiffs_dbg_flag & 32) printf("my_spi_write(0x%x, %u, 0x%lx)\n", (unsigned) addr, (unsigned) size, (unsigned long) src);
	if (spiffs_dbg_flag & 128)
	{
	    register long a1 asm ("a1");
	    register long a15 asm ("a15");
	    printf("a1 is %lx and a15 is %lx\n", a1, a15);
	}

#ifdef SIMULATE_FLASH
	memcpy(simulated_flash+addr-SPIFFS_CFG_PHYS_ADDR(), src, size);
    return SPIFFS_OK;
#else
	SpiFlashOpResult result;
	uint_fast8_t preamble = - (uint_fast8_t) src & 3;

	// spi_flash_write needs aligned data (as documented) and it
	// deems soesn't behave unless writes are a multiple of 4
	if (preamble)
	{
		uint32 buffer = 0xffffffff;
		if (size < preamble) preamble = size;
		memcpy(&buffer, src, preamble);
		if (spiffs_dbg_flag & 32) printf("spi_flash_write(%x, new data1 %x, %u to four)\n", (unsigned) addr, (unsigned) buffer, (unsigned) preamble);
		result = spi_flash_write(addr, &buffer, 4);
		if (result != SPI_FLASH_RESULT_OK) return result == SPI_FLASH_RESULT_TIMEOUT ? MP_ETIMEDOUT : MP_EIO;
		src  += preamble;
		addr += preamble;
		size -= preamble;
	}
	if (size >= 4)
	{
		u32_t body = size & ~3;
		if (spiffs_dbg_flag & 32) printf("spi_flash_write(%x, %x, %u)\n", (unsigned) addr, (unsigned) src, (unsigned) body);
		result = spi_flash_write(addr, (uint32 *)src, body);
		if (result != SPI_FLASH_RESULT_OK) return result == SPI_FLASH_RESULT_TIMEOUT ? MP_ETIMEDOUT : MP_EIO;
		src  += body;
		addr += body;
		size -= body;
	}
	if (size)
	{
		uint32 buffer = 0xffffffff;
		memcpy(&buffer, src, size);
		if (spiffs_dbg_flag & 32) printf("spi_flash_write(%x, new data2 %x, %u to four)\n", (unsigned) addr, (unsigned) buffer, (unsigned) size);
		result = spi_flash_write(addr, &buffer, 4);
		if (result != SPI_FLASH_RESULT_OK) return result == SPI_FLASH_RESULT_TIMEOUT ? MP_ETIMEDOUT : MP_EIO;
	}

	return SPIFFS_OK;
#endif
}

static s32_t my_spi_erase(u32_t addr, u32_t size) {
	if (spiffs_dbg_flag & 32) printf("my_spi_erase(0x%x, %u)\n", (unsigned) addr, (unsigned) size);
	  if (size != 4096)
	  {
		  printf("Attempt to erase %u bytes !", (unsigned) size);
		  return EIO;
	  }
#ifdef SIMULATE_FLASH
	memset(simulated_flash+addr-SPIFFS_CFG_PHYS_ADDR(), 0xff, size);
	return SPIFFS_OK;
#else
	ets_loop_iter();
	SpiFlashOpResult result = spi_flash_erase_sector(addr/SPI_FLASH_SEC_SIZE);
	return result == SPI_FLASH_RESULT_OK ? SPIFFS_OK : EIO;
#endif
}

#define LOG_PAGE_SIZE       128

static u8_t spiffs_fds[32*4];
static u8_t spiffs_work_buf[LOG_PAGE_SIZE*2];
static u32_t spiffs_cache_buf[(LOG_PAGE_SIZE+32)];

STATIC mp_obj_t SPIFFS_vfs_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
	// short circuit
	if (fs.fs.mounted) return MP_OBJ_FROM_PTR(&fs);

    mp_arg_check_num(n_args, n_kw, 0, 0, false);
	mp_obj_SPIFFS_vfs_t *vfs = &fs;
    vfs->base.type = type;

    spiffs_config cfg;

    cfg.hal_read_f = my_spi_read;
    cfg.hal_write_f = my_spi_write;
    cfg.hal_erase_f = my_spi_erase;

    int res = SPIFFS_mount(&vfs->fs, &cfg, (u8_t *) spiffs_work_buf, spiffs_fds, sizeof spiffs_fds, spiffs_cache_buf, sizeof spiffs_cache_buf, 0);
    if (res != SPIFFS_OK)
    {
    	printf("First mount failed. Attempting format.\n");
    	res = SPIFFS_format(&vfs->fs);
    	if (res != SPIFFS_OK)
    	{
    		printf("format failed.");
            nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(SPIFFS_errno(&fs.fs))));
    	}
        res = SPIFFS_mount(&vfs->fs, &cfg, (u8_t *) spiffs_work_buf, spiffs_fds, sizeof spiffs_fds, spiffs_cache_buf, sizeof spiffs_cache_buf, 0);
    	if (res != SPIFFS_OK)
    	{
    		printf("Second attempt to mount failed.");
            nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(SPIFFS_errno(&fs.fs))));
    	}
    }

    return MP_OBJ_FROM_PTR(vfs);
}

STATIC const mp_arg_t file_open_args[] = {
    { MP_QSTR_file, MP_ARG_OBJ | MP_ARG_REQUIRED, {.u_rom_obj = MP_ROM_PTR(&mp_const_none_obj)} },
    { MP_QSTR_mode, MP_ARG_OBJ, {.u_obj = MP_OBJ_NEW_QSTR(MP_QSTR_r)} }
};
#define FILE_OPEN_NUM_ARGS MP_ARRAY_SIZE(file_open_args)

STATIC mp_obj_t file_open(const mp_obj_type_t *type, mp_arg_val_t *args) {
    int mode = 0;
    const char *mode_s = mp_obj_str_get_str(args[1].u_obj);
    // TODO make sure only one of r, w, x, a, and b, t are specified
    while (*mode_s) {
        switch (*mode_s++) {
            case 'r':
                mode = SPIFFS_O_RDONLY;
                break;
            case 'w':
                mode = SPIFFS_O_WRONLY | SPIFFS_O_TRUNC | SPIFFS_O_CREAT;
                break;
            case 'x':
                mode = SPIFFS_O_WRONLY | SPIFFS_O_CREAT | SPIFFS_O_EXCL;
                break;
            case 'a':
                mode = SPIFFS_O_WRONLY | SPIFFS_O_CREAT | SPIFFS_O_APPEND;
                break;
            case 'd':
                mode = SPIFFS_O_DIRECT;
                break;
            case '+':
                mode |=  SPIFFS_O_RDWR;
                mode &= ~SPIFFS_O_TRUNC;
                break;
            #if MICROPY_PY_IO_FILEIO
            case 'b':
                type = &spiffs_type_fileio;
                break;
            #endif
            case 't':
                type = &spiffs_type_textio;
                break;
        }
    }

    SPIFFS_file_t *o = m_new_obj_with_finaliser(SPIFFS_file_t);
    o->base.type = type;

    const char *fname = mp_obj_str_get_str(args[0].u_obj);
    spiffs_file res = SPIFFS_open(&fs.fs, fname, mode, 0);
    // printf("SPIFFS_open(%s)->%d\n", fname, (int)res);

    if (res < 0) {
        m_del_obj(SPIFFS_file_t, o);
        nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError, MP_OBJ_NEW_SMALL_INT(SPIFFS_errno(&fs.fs))));
    }
    o->handle = res;

    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t file_obj_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_val_t arg_vals[FILE_OPEN_NUM_ARGS];
    mp_arg_parse_all_kw_array(n_args, n_kw, args, FILE_OPEN_NUM_ARGS, file_open_args, arg_vals);
    return file_open(type, arg_vals);
}

STATIC void file_obj_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind) {
    (void)kind;
    mp_printf(print, "<io.%s %p>", mp_obj_get_type_str(self_in), MP_OBJ_TO_PTR(self_in));
}

STATIC mp_uint_t file_obj_read(mp_obj_t self_in, void *buf, mp_uint_t size, int *errcode) {
	SPIFFS_file_t *self = MP_OBJ_TO_PTR(self_in);

    s32_t res = SPIFFS_read(&fs.fs, self->handle, buf, size);
    // printf("SPIFFS_read(%d, %lu)->%d\n", (int)self->handle, (unsigned long)size, (int)res);
    if (res == SPIFFS_ERR_END_OF_OBJECT) return 0;
    if (res < 0) {
        *errcode = SPIFFS_errno(&fs.fs);
        return MP_STREAM_ERROR;
    }
    return res;
}

STATIC mp_uint_t file_obj_write(mp_obj_t self_in, const void *buf, mp_uint_t size, int *errcode) {
	SPIFFS_file_t *self = MP_OBJ_TO_PTR(self_in);

    s32_t res = SPIFFS_write(&fs.fs, self->handle, (void *)buf, size); // TODO get SPIFFS need for unconstify fixed
    if (res < 0) {
    	*errcode = SPIFFS_errno(&fs.fs);
        return MP_STREAM_ERROR;
    }
    return res;
}

STATIC mp_obj_t file_obj_flush(mp_obj_t self_in) {
	SPIFFS_file_t *self = MP_OBJ_TO_PTR(self_in);
    /* s32_t res = */ SPIFFS_fflush(&fs.fs, self->handle);
    // printf("SPIFFS_flush(%d)->%d\n", (int)self->handle, (int)res);
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(file_obj_flush_obj, file_obj_flush);

// inherited TODO gc hook to close the file if not already closed
STATIC mp_obj_t file_obj_close(mp_obj_t self_in) {
	SPIFFS_file_t *self = MP_OBJ_TO_PTR(self_in);
    s32_t res = SPIFFS_close(&fs.fs, self->handle);
    // printf("SPIFFS_close(%d)->%d\n", (int)self->handle, (int)res);

    return res == SPIFFS_OK ? mp_const_none : MP_OBJ_NEW_SMALL_INT(res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(file_obj_close_obj, file_obj_close);

STATIC mp_obj_t file_obj___exit__(size_t n_args, const mp_obj_t *args) {
    (void)n_args;
    return file_obj_close(args[0]);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(file_obj___exit___obj, 4, 4, file_obj___exit__);

STATIC const mp_rom_map_elem_t rawfile_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_read), MP_ROM_PTR(&mp_stream_read_obj) },
    { MP_ROM_QSTR(MP_QSTR_readall), MP_ROM_PTR(&mp_stream_readall_obj) },
    { MP_ROM_QSTR(MP_QSTR_readinto), MP_ROM_PTR(&mp_stream_readinto_obj) },
    { MP_ROM_QSTR(MP_QSTR_readline), MP_ROM_PTR(&mp_stream_unbuffered_readline_obj) },
    { MP_ROM_QSTR(MP_QSTR_readlines), MP_ROM_PTR(&mp_stream_unbuffered_readlines_obj) },
    { MP_ROM_QSTR(MP_QSTR_write), MP_ROM_PTR(&mp_stream_write_obj) },
    { MP_ROM_QSTR(MP_QSTR_flush), MP_ROM_PTR(&file_obj_flush_obj) },
    { MP_ROM_QSTR(MP_QSTR_close), MP_ROM_PTR(&file_obj_close_obj) },
    { MP_ROM_QSTR(MP_QSTR_seek), MP_ROM_PTR(&mp_stream_seek_obj) },
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&file_obj_close_obj) },
    { MP_ROM_QSTR(MP_QSTR___enter__), MP_ROM_PTR(&mp_identity_obj) },
    { MP_ROM_QSTR(MP_QSTR___exit__), MP_ROM_PTR(&file_obj___exit___obj) },
};

STATIC MP_DEFINE_CONST_DICT(rawfile_locals_dict, rawfile_locals_dict_table);

#if MICROPY_PY_IO_FILEIO
STATIC const mp_stream_p_t fileio_stream_p = {
    .read = file_obj_read,
    .write = file_obj_write,
    //.ioctl = file_obj_ioctl,
};

const mp_obj_type_t spiffs_type_fileio = {
    { &mp_type_type },
    .name = MP_QSTR_FileIO,
    .print = file_obj_print,
    .make_new = file_obj_make_new,
    .getiter = mp_identity,
    .iternext = mp_stream_unbuffered_iter,
    .protocol = &fileio_stream_p,
    .locals_dict = (mp_obj_dict_t*)&rawfile_locals_dict,
};
#endif

STATIC const mp_stream_p_t textio_stream_p = {
    .read = file_obj_read,
    .write = file_obj_write,
    // .ioctl = file_obj_ioctl,
    .is_text = true,
};

const mp_obj_type_t spiffs_type_textio = {
    { &mp_type_type },
    .name = MP_QSTR_TextIOWrapper,
    .print = file_obj_print,
    .make_new = file_obj_make_new,
    .getiter = mp_identity,
    .iternext = mp_stream_unbuffered_iter,
    .protocol = &textio_stream_p,
    .locals_dict = (mp_obj_dict_t*)&rawfile_locals_dict,
};

// Factory function for I/O stream classes
mp_obj_t SPIFFS_builtin_open(mp_uint_t n_args, const mp_obj_t *args, mp_map_t *kwargs) {
    // TODO: analyze buffering args and instantiate appropriate type
    mp_arg_val_t arg_vals[FILE_OPEN_NUM_ARGS];
    mp_arg_parse_all(n_args, args, kwargs, FILE_OPEN_NUM_ARGS, file_open_args, arg_vals);
    return file_open(&spiffs_type_textio, arg_vals);
}

STATIC mp_obj_t SPIFFS_vfs_open(size_t n_args, const mp_obj_t *args, mp_map_t *kwargs) {
    // Skip self
    return SPIFFS_builtin_open(n_args - 1, args + 1, kwargs);
}
MP_DEFINE_CONST_FUN_OBJ_KW(SPIFFS_vfs_open_obj, 2, SPIFFS_vfs_open);

STATIC mp_obj_t SPIFFS_vfs_remove(mp_obj_t vfs_in, mp_obj_t path_in) {
    (void)vfs_in;
    const char *path = mp_obj_str_get_str(path_in);
    // TODO check that path is actually a file before trying to unlink it
    s32_t res = SPIFFS_remove(&fs.fs, path);
    if (res == SPIFFS_OK) {
        return mp_const_none;
    } else {
        nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError,
            MP_OBJ_NEW_SMALL_INT(SPIFFS_errno(&fs.fs))));
    }
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(SPIFFS_vfs_remove_obj, SPIFFS_vfs_remove);

STATIC mp_obj_t SPIFFS_vfs_rename(mp_obj_t vfs_in, mp_obj_t path_in, mp_obj_t path_out) {
    (void)vfs_in;
    const char *old_path = mp_obj_str_get_str(path_in);
    const char *new_path = mp_obj_str_get_str(path_out);
    s32_t res = SPIFFS_rename(&fs.fs, old_path, new_path);
    if (res == SPIFFS_OK) {
        return mp_const_none;
    } else {
        nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError,
            MP_OBJ_NEW_SMALL_INT(SPIFFS_errno(&fs.fs))));
    }
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(SPIFFS_vfs_rename_obj, SPIFFS_vfs_rename);

STATIC mp_obj_t SPIFFS_vfs_listdir_func(size_t n_args, const mp_obj_t *args) {

	bool is_str_type = true;

	if (n_args == 2 && mp_obj_get_type(args[1]) == &mp_type_bytes) is_str_type = false;

	spiffs_DIR dir;
	spiffs_DIR *d2 = SPIFFS_opendir(&fs.fs, NULL, &dir);

	if (!d2) {
		nlr_raise(mp_obj_new_exception_arg1(&mp_type_OSError,
		MP_OBJ_NEW_SMALL_INT(SPIFFS_errno(&fs.fs))));
    }
    mp_obj_t dir_list = mp_obj_new_list(0, NULL);

	struct spiffs_dirent e;
	while (SPIFFS_readdir(&dir, &e))
	{
		mp_obj_t entry_o;
	    if (is_str_type) {
	    	entry_o = mp_obj_new_str((char *)e.name, strlen((char *)e.name), false);
	      	  } else {
	      		  entry_o = mp_obj_new_bytes((const byte*)e.name, strlen((char *)e.name));
	        }

        mp_obj_list_append(dir_list, entry_o);
	}
    return dir_list;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(SPIFFS_vfs_listdir_obj, 1, 1, SPIFFS_vfs_listdir_func);

// filesystem methods
STATIC const mp_rom_map_elem_t SPIFFS_vfs_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_open), MP_ROM_PTR(&SPIFFS_vfs_open_obj) },
    { MP_ROM_QSTR(MP_QSTR_listdir), MP_ROM_PTR(&SPIFFS_vfs_listdir_obj) },
    { MP_ROM_QSTR(MP_QSTR_remove), MP_ROM_PTR(&SPIFFS_vfs_remove_obj) },
    { MP_ROM_QSTR(MP_QSTR_rename), MP_ROM_PTR(&SPIFFS_vfs_rename_obj) },
   // { MP_ROM_QSTR(MP_QSTR_stat), MP_ROM_PTR(&SPIFFS_vfs_stat_obj) }
};

STATIC MP_DEFINE_CONST_DICT(SPIFFS_vfs_locals_dict, SPIFFS_vfs_locals_dict_table);

const mp_obj_type_t mp_SPIFFS_vfs_type = {
    { &mp_type_type },
    .name = MP_QSTR_VfsSPIFFS,
    .make_new = SPIFFS_vfs_make_new,
    .locals_dict = (mp_obj_dict_t*)&SPIFFS_vfs_locals_dict,
};

STATIC mp_obj_t spiffs_format()
{
	s32_t res = SPIFFS_format(&fs.fs);
    return MP_OBJ_NEW_SMALL_INT(res);
}

MP_DEFINE_CONST_FUN_OBJ_0(mod_format_obj, spiffs_format);

STATIC mp_obj_t spiffs_diagnose(size_t n_args, const mp_obj_t *args)
{
	// printf("%lu %lu %lu", n_args, mp_obj_get_int(args[0]), mp_obj_get_int(args[1]));
	if (n_args == 2 && mp_obj_get_int(args[0]) == 7)
	{
		spiffs_dbg_flag = (u8_t) mp_obj_get_int(args[1]);
		printf("set SPIFFS debug flag\n");
	}
	if (n_args == 1 && mp_obj_get_int(args[0]) == 8)
	{
	    register long a1 asm ("a1");
	    register long a15 asm ("a15");
	    printf("a1 is %lx and a15 is %lx\n", a1, a15);
	}
	if (n_args == 1 && mp_obj_get_int(args[0]) == 9)
	{
		SPIFFS_unmount(&fs.fs);
	}
	return mp_const_none;
}

MP_DEFINE_CONST_FUN_OBJ_VAR(mod_diagnose_obj, 0, spiffs_diagnose);

// module globals
STATIC const mp_rom_map_elem_t spiffs_module_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_spiffs) },
    { MP_ROM_QSTR(MP_QSTR_SPIFFS), MP_ROM_PTR(&mp_SPIFFS_vfs_type) }, // constructor
    { MP_ROM_QSTR(MP_QSTR_format), MP_ROM_PTR(&mod_format_obj) },
    { MP_ROM_QSTR(MP_QSTR_diagnose), MP_ROM_PTR(&mod_diagnose_obj) },
};

STATIC MP_DEFINE_CONST_DICT(spiffs_module_globals, spiffs_module_globals_table);

const mp_obj_module_t mp_module_spiffs = {
    .base = { &mp_type_module },
    .name = MP_QSTR_spiffs,
    .globals = (mp_obj_dict_t*)&spiffs_module_globals,
};
