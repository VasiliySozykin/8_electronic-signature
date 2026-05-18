import random
from gostcrypto import gosthash
# 1. Параметры эллептической кривой (ГОСТ Р 34.10-2012, 256 бит, ParamSetA)
p =  int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97', 16)
a =  int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94', 16)
b =  int('A7C5C5C9D749B45C0B7CE5F3A1CE2826AF96C61CC35AA15B9D19D0A805FF7DDE', 16)
q =  int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893', 16)
Px = int('0000000000000000000000000000000000000000000000000000000000000001', 16)
Py = int('8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14', 16)
P = (Px, Py) # Базовая точка
# 2. Матемтика эллиптических кривых и модульная арифметика
def egcd(a, b):
    """Расширенный алгоритм Евклида."""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def mod_inverse(a, m):
    """Нахождение обратного элемента по модулю."""
    a = a % m
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception(f'Обратного элемента не существует (НОД={g}). Модуль не является простым числом!')
    else:
        return x % m

def ec_add(p1, p2):
    """Сложение двух точек на эллиптической кривой."""
    if p1 is None: return p2
    if p2 is None: return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 != y2:
        return None # Точки симметричны, результат - бесконечно удаленная точка 0

    if x1 == x2:
        # Удвоение точки
        lam = (3 * x1 * x1 + a) * mod_inverse(2 * y1, p) % p
    else:
        # Сложение разных точек
        lam = (y2 - y1) * mod_inverse(x2 - x1, p) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def ec_mult(k, point):
    """Умножение точки на скаляр (Double-and-Add)."""
    result = None
    addend = point

    while k:
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result

# 3. Алгоритмы ГОСТ
def generate_keys():
    """Генерация закрытого (d) и открытого (Q) ключей."""
    d = random.SystemRandom().randint(1, q - 1)
    Q = ec_mult(d, P)                           
    return d, Q

def sign(msg_bytes, d):
    """Формирование электронной подписи (ЭП)."""
    h_bytes = gosthash.new('streebog256', data=msg_bytes).digest()
    
    e = int.from_bytes(h_bytes, byteorder='big') % q
    if e == 0: e = 1

    while True:
        k = random.SystemRandom().randint(1, q - 1)
        C = ec_mult(k, P)
        
        r = C[0] % q
        if r == 0: continue
            
        s = (r * d + k * e) % q
        if s == 0: continue
            
        r_bytes = r.to_bytes(32, byteorder='big')
        s_bytes = s.to_bytes(32, byteorder='big')
        return r_bytes + s_bytes

def verify(msg_bytes, signature, Q):
    """Проверка электронной подписи."""
    if len(signature) != 64:
        print("Ошибка: неверная длина подписи.")
        return False
        
    r = int.from_bytes(signature[:32], byteorder='big')
    s = int.from_bytes(signature[32:], byteorder='big')
    
    if not (0 < r < q and 0 < s < q):
        return False
        
    h_bytes = gosthash.new('streebog256', data=msg_bytes).digest()
    
    e = int.from_bytes(h_bytes, byteorder='big') % q
    if e == 0: e = 1
        
    v = mod_inverse(e, q)
    z1 = (s * v) % q
    z2 = (-r * v) % q
    
    C1 = ec_mult(z1, P)
    C2 = ec_mult(z2, Q)
    C = ec_add(C1, C2)
    
    if C is None:
        return False
        
    R = C[0] % q
    return R == r
# 4. Интерфейс и работа с файлами
def main():
    print("(Электронная подпись)")
    while True:
        print("\nВыберите действие:")
        print("1. Сгенерировать ключи")
        print("2. Подписать файл")
        print("3. Проверить подпись")
        print("0. Выход")
        
        choice = input("> ")
        
        if choice == '1':
            print("Генерация ключей...")
            d, Q = generate_keys()
            with open('private.key', 'w') as f:
                f.write(hex(d))
            with open('public.key', 'w') as f:
                f.write(f"{hex(Q[0])}\n{hex(Q[1])}")
            print("Ключи успешно сгенерированы и сохранены в 'private.key' и 'public.key'.")
            
        elif choice == '2':
            file_path = input("Введите путь к файлу для подписи: ")
            try:
                with open(file_path, 'rb') as f:
                    msg = f.read()
                with open('private.key', 'r') as f:
                    d = int(f.read().strip(), 16)
                    
                print("Вычисление подписи...")
                sig = sign(msg, d)
                
                sig_path = file_path + ".sig"
                with open(sig_path, 'wb') as f:
                    f.write(sig)
                print(f"Файл успешно подписан. Подпись сохранена в '{sig_path}'.")
                
            except Exception as e:
                print(f"[-] Ошибка при подписании: {e}")
                
        elif choice == '3':
            file_path = input("Введите путь к исходному файлу: ")
            sig_path = input("Введите путь к файлу подписи (.sig): ")
            try:
                with open(file_path, 'rb') as f:
                    msg = f.read()
                with open(sig_path, 'rb') as f:
                    sig = f.read()
                with open('public.key', 'r') as f:
                    lines = f.readlines()
                    Q = (int(lines[0].strip(), 16), int(lines[1].strip(), 16))
                    
                is_valid = verify(msg, sig, Q)
                
                if is_valid:
                    print("ПОДПИСЬ ВЕРНА! Документ подлинный.")
                else:
                    print("ПОДПИСЬ НЕВЕРНА! Документ скомпрометирован.")
                    
            except Exception as e:
                print(f"[-] Ошибка при проверке: {e}")
                
        elif choice == '0':
            break
        else:
            print("Неверный выбор.")

if __name__ == '__main__':
    main()