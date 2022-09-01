```python

from protected import dump, load, generate_fernet_key

class Example:
    secret = "secretsecretigotasecret"
    data = { "a":1, "b":2, "c":3 }
    def get_data(self, key:str) -> int: return self.data[key]

ex = Example()

print(ex.get_data("a"), ex.get_data("b"), ex.get_data("c"))

fernet_key = generate_fernet_key()

with open("example.pkl", "wb") as file: 
    digital_signature = dump(fernet_key, ex, file)

with open("example.pkl", "rb") as file: 
    new_ex = load(fernet_key, digital_signature, file)

print(new_ex.get_data("a"), new_ex.get_data("b"), new_ex.get_data("c"))

```