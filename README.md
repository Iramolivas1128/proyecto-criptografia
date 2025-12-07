# proyecto-criptografia
Algoritmo de cifrado

# Proyecto CIPHERX-128

Repositorio del proyecto académico de criptografía.

## Estructura
- `sandbox/` : carpeta obligatoria donde opera la aplicación.
  - `in/` : entrada de archivos de prueba
  - `out/` : salidas
  - `keys/` : claves generadas por `init`
- `escrow/` : archivo `recovery.enc` generado en demo
- `src/` : código fuente
- `tests/` : pruebas automatizadas (pytest)
- `execution.log` : log de ejecuciones

## Requisitos (instalar)
```bash
python -m pip install -r requirements.txt

```
## Cómo Ejecutar
1.- Instalar dependencias
```bash
python -m pip install -r requirements.txt
```
2.- Inicializar el sistema
```bash
python -m src.cli init
```
3.- Crear mensaje
```bash
echo "Criptografia" > sandbox/in/prueba.txt
```
4.- Cifrar
```bash
python -m src.cli encrypt \
    --infile sandbox/in/prueba2.txt \
    --outfile sandbox/out/prueba2.txt.enc \
    --keyfile sandbox/keys/key.bin
```
5.- Descifrar
```bash
python -m src.cli decrypt \
    --infile sandbox/out/prueba2.txt.enc \
    --outfile sandbox/out/prueba_decrypted2.txt \
    --keyfile sandbox/keys/key.bin
```
6.- Ejecutar pruebas
```
PYTHONPATH=. pytest -q
