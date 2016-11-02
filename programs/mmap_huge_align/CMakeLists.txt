cmake_minimum_required(VERSION 2.6)

project(malloc_huge)

file(GLOB SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.c)
file(GLOB HDR RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.h)

foreach(source_file ${SRC})
	string(REPLACE ".c" "" exe ${source_file})
	MESSAGE(STATUS "src: " ${source_file})
	MESSAGE(STATUS "exe: " ${exe})
	add_executable(${exe} ${source_file})
endforeach(source_file)
