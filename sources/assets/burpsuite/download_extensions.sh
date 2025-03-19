cat extensions.txt | while read -r line; do
    extension_name=$(echo $line | awk -F '/' '{print $NF}')
    git clone "$line" "/opt/tools/BurpSuiteCommunity/extensions/$extension_name"
done