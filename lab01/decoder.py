def solve_it(problem):
    leng = (len(problem) - 4) // 35
    datas = []
    for i in range(leng):
        temp = ''
        for row in range(5):
            temp += problem[row * (leng * 7 + 1) + 7 * i: row * (leng * 7 + 1) + 7 * (i + 1)]+'\n'
        print(temp)
        datas.append(temp)
    
    symbols = []

with open('test.txt','r') as f:
    data = f.read()
    solve_it(data)