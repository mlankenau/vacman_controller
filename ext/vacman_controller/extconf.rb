require 'mkmf'

if find_library('aal2sdk-3.11.2', 'AAL2DPXInit', '/opt/vasco/VACMAN_Controller-3.11.2/lib')
  create_makefile('vacman_controller/vacman_controller')
 else
  puts "No libaal2sdk found"
  exit 1
end