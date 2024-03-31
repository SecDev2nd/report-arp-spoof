# 최소한의 CMake 버전 요구
cmake_minimum_required(VERSION 3.10)

# 프로젝트 이름 설정
project(arp-spoof)

# 헤더 파일이 위치한 경로 추가
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../header)

# 모든 소스 파일을 소스 변수에 추가
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/arphdr.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ethhdr.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ip.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/mac.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/Utill.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/main.cpp
)

# 실행 파일 생성
add_executable(report-arp-spoof ${SOURCES})

# 라이브러리 링크
target_link_libraries(report-arp-spoof pcap)
