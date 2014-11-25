
open OUnit2

let () =
  run_test_tt_main ("dns" >::: [
      Test_packet.tests;
    ])

