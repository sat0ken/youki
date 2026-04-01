#!/bin/bash

function do_test() {
  if [ -f ./libseccomp-2.6.0/tests/$1 ]; then
      rm ./libseccomp-2.6.0/tests/$1
  fi
  cargo build --example $1
  cp ./target/debug/examples/$1 ./libseccomp-2.6.0/tests/$1
  cd ./libseccomp-2.6.0/tests
  ./regression -b $1
}

case $1 in
  "01")
    do_test 01-sim-allow
    ;;
  "02")
    do_test 02-sim-basic
    ;;
  "03")
    do_test 03-sim-basic_chains
    ;;
  "04")
    do_test 04-sim-multilevel_chains
    ;;
  "06")
    do_test 06-sim-actions
    ;;
  "07")
    do_test 07-sim-db_bug_looping
    ;;
  "08")
    do_test 08-sim-subtree_checks
    ;;
  "18")
    do_test 18-sim-basic_allowlist
    ;;
  "25")
    do_test 25-sim-multilevel_chains_adv
    ;;
  "28")
    do_test 28-sim-arch_x86
    ;;
  "30")
    do_test 30-sim-socket_syscalls
    ;;
  "34")
    do_test 34-sim-basic_denylist
    ;;
esac