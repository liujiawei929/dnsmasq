# Makefile for Site Filter - OpenWrt站点过滤模块

# 编译器和编译选项
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=gnu99
LDFLAGS = 
LIBS = 

# 安装路径
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
SBINDIR = $(PREFIX)/sbin
SYSCONFDIR = /etc
INITDIR = /etc/init.d
MANDIR = $(PREFIX)/share/man

# 源文件和目标文件
SRCDIR = src
SOURCES = $(SRCDIR)/site_filter.c
HEADERS = $(SRCDIR)/site_filter.h
TARGET = site_filter
CONFIG = site_filter.conf
INITSCRIPT = init.d/site_filter

# 构建目标
all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS) $(LIBS)

# 清理编译文件
clean:
	rm -f $(TARGET)
	rm -f *.o

# 安装
install: $(TARGET)
	@echo "Installing Site Filter..."
	install -d $(DESTDIR)$(SBINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(SBINDIR)/
	install -d $(DESTDIR)$(SYSCONFDIR)
	install -m 644 $(CONFIG) $(DESTDIR)$(SYSCONFDIR)/
	install -d $(DESTDIR)$(INITDIR)
	install -m 755 $(INITSCRIPT) $(DESTDIR)$(INITDIR)/
	@echo "Installation completed."

# 卸载
uninstall:
	@echo "Uninstalling Site Filter..."
	rm -f $(DESTDIR)$(SBINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(SYSCONFDIR)/$(CONFIG)
	rm -f $(DESTDIR)$(INITDIR)/site_filter
	@echo "Uninstallation completed."

# 开发者目标
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# 静态分析
check:
	@echo "Running static analysis..."
	@which cppcheck >/dev/null 2>&1 && cppcheck --enable=all $(SOURCES) || echo "cppcheck not found"

# 代码格式化
format:
	@echo "Formatting code..."
	@which indent >/dev/null 2>&1 && indent -linux $(SOURCES) $(HEADERS) || echo "indent not found"

# 测试
test: $(TARGET)
	@echo "Running basic tests..."
	./$(TARGET) -h
	@echo "Basic tests passed."

# OpenWrt相关目标
openwrt-package:
	@echo "Creating OpenWrt package structure..."
	mkdir -p package/site-filter/src
	cp $(SOURCES) $(HEADERS) package/site-filter/src/
	cp $(CONFIG) package/site-filter/
	cp $(INITSCRIPT) package/site-filter/
	cp openwrt/Makefile package/site-filter/
	@echo "OpenWrt package structure created in package/site-filter/"

# 创建发布包
dist: clean
	@echo "Creating distribution package..."
	tar czf site-filter-1.0.tar.gz $(SOURCES) $(HEADERS) $(CONFIG) $(INITSCRIPT) Makefile README.md
	@echo "Distribution package created: site-filter-1.0.tar.gz"

# 帮助信息
help:
	@echo "Site Filter - OpenWrt站点过滤模块"
	@echo ""
	@echo "可用目标:"
	@echo "  all          - 编译程序 (默认)"
	@echo "  clean        - 清理编译文件"
	@echo "  install      - 安装程序和配置文件"
	@echo "  uninstall    - 卸载程序"
	@echo "  debug        - 编译调试版本"
	@echo "  check        - 运行静态代码分析"
	@echo "  format       - 格式化代码"
	@echo "  test         - 运行基本测试"
	@echo "  openwrt-package - 创建OpenWrt包结构"
	@echo "  dist         - 创建发布包"
	@echo "  help         - 显示此帮助信息"

.PHONY: all clean install uninstall debug check format test openwrt-package dist help
