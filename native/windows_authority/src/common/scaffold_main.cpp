#include <iostream>

#ifndef FAULTLOOM_COMPONENT
#error FAULTLOOM_COMPONENT must name the scaffold executable
#endif

int wmain() {
  std::wcout << L"FaultLoom Windows Authority " << FAULTLOOM_COMPONENT << L" scaffold\n";
  return 0;
}
