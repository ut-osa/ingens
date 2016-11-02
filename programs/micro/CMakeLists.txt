cmake_minimum_required(VERSION 2.6)

set(CMAKE_CXX_COMPILER "g++")

project(memhog)
set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pthread")
file(GLOB SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.c)
file(GLOB HDR RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.h)

#find_library(lib1_location lib1)
#message("Lib1 is at: ${lib1_location}")
#target_link_libraries(lib2 LINK_PUBLIC ${lib1_location})

foreach(source_file ${SRC})
	string(REPLACE ".c" "" exe ${source_file})
	MESSAGE(STATUS "src: " ${source_file})
	MESSAGE(STATUS "exe: " ${exe})
	add_executable(${exe} ${source_file})
	target_link_libraries(${exe} pthread)
endforeach(source_file)
