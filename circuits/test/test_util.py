import subprocess
import os
import shutil

TC = os.path.join(".", "test_circuits")
CF = ["--r1cs", "--c", "--prime", "secq256k1", "--O2"]
FNULL = open(os.devnull, 'w')

def run_circom(circuit_name):
    try:
        subprocess.run(args=["circom", f"{circuit_name}.circom"] + CF, check=True, cwd=TC, stdout=FNULL, 
    stderr=subprocess.STDOUT)
    except Exception:
        return False, False, False
    
    try:
        subprocess.run(args=["make"], check=True, cwd=os.path.join(TC, f"{circuit_name}_cpp"), stdout=FNULL, 
    stderr=subprocess.STDOUT)
    except Exception:
        return True, False, False
    
    try:
        subprocess.run(args=[f"./{circuit_name}", "../input.json", "witness.wtns"], check=True, cwd=os.path.join(TC, f"{circuit_name}_cpp"), stdout=FNULL, 
    stderr=subprocess.STDOUT)
        return True, True, True
    except Exception:
        return True, True, False
    
def clean(circuit_name):
    try:
        os.remove(os.path.join(TC, f"{circuit_name}.r1cs"))
        shutil.rmtree(os.path.join(TC, f"{circuit_name}_cpp"))
    except Exception:
        pass