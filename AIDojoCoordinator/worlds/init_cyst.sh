# create cyst
curl -X POST http://127.0.0.1:8000/api/v1/environment/create/ \
     -H "Content-Type: application/json" \
     -d "{
           \"id\": \"coordinator_cyst\",
           \"platform\": {
             \"type\": 2,
             \"provider\": \"CYST\"
           },
           \"configuration\": \"demo_configuration\"
         }"
# init cyst
curl -X POST "http://127.0.0.1:8000/api/v1/environment/init/?id=coordinator_cyst" \
     -H "Content-Type: application/json"
# run cyst
curl -X POST "http://127.0.0.1:8000/api/v1/environment/run/?id=coordinator_cyst" \
     -H "Content-Type: application/json"