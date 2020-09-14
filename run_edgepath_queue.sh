export FILTER_NAME=MQfilter
export ROOT_CHECK=/home/cju/sp2021/e2e_sche/filter_jobs
export ROOT_WRITE=/home/cju/sp2021/e2e_sche/findings_dir

export WHO_BIN=/home/cju/sp2021/e2e_sche/readelf_vani

# for who
rm -rf /home/cju/sp2021/e2e_sche/filter_jobs/*
rm -rf /home/cju/sp2021/e2e_sche/findings_dir/MQfilter
rm -rf /home/cju/sp2021/e2e_sche/findings_dir/MQfilter-path 
mkdir -p /home/cju/sp2021/e2e_sche/findings_dir/MQfilter-path/_queue
mkdir -p /home/cju/sp2021/e2e_sche/findings_dir/MQfilter-path/_crashes
AFL_SKIP_CPUFREQ=1 ./afl-fuzz -Q -m 1024 -t 90 -S $FILTER_NAME -s $ROOT_CHECK -o $ROOT_WRITE -- $WHO_BIN -a @@
