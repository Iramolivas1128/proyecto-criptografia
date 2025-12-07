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
3.- Cifrar
```bash
python -m src.cli encrypt --infile sandbox/in/file.txt --outfile sandbox/out/file.enc --keyfile sandbox/keys/key.bin
```
4.- Descifrar
```bash
python -m src.cli decrypt --infile sandbox/out/file.enc --outfile sandbox/out/file_dec.txt --keyfile sandbox/keys/key.bin
```
5.- Ejecutar pruebas
```
PYTHONPATH=. pytest -q
