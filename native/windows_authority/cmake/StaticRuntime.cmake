if(NOT MSVC)
  message(FATAL_ERROR "FaultLoom Windows Authority requires MSVC")
endif()

if(NOT FAULTLOOM_STATIC_CRT)
  message(FATAL_ERROR "FAULTLOOM_STATIC_CRT must remain ON")
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
