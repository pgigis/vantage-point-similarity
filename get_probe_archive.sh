DAYS_ARRAY=(
    '01' '02' '03' '04' '05' '06' '07'
    )

for day in ${DAYS_ARRAY[@]}
do
    	wget -bcq https://ftp.ripe.net/ripe/atlas/probes/archive/2018/04/201804$day.json.bz2 -P /Users/pgigis/git/probe-similarity/new/probe_archive/
done