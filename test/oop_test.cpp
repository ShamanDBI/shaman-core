#include <iostream>
using namespace std;

using jump_func_t = void (*)(void const *);
template <class F>
jump_func_t jump_func()
{
    return [](void const *ptr)
    { (*static_cast<F const *>(ptr))(); };
}
template <class... Fs>
void jump_table(std::size_t i, Fs const &...fs)
{
    struct entry
    {
        jump_func_t f;
        void const *data;
        void operator()() const { f(data); }
    };
    const entry table[] = {
        {jump_func<Fs>(), std::addressof(fs)}...};
    table[i]();
}

// base class
class Vehicle
{
public:
    string brand;

    void show_brand()
    {
        cout << "Brand: " << brand << endl;
    }
};

class Car : public Vehicle
{
public:
    // class data
    string brand, model;
    int mileage = 0;

    // class function to drive the car
    void drive(int distance)
    {
        mileage += distance;
    }

    // class function to print variables
    void show_data()
    {
        Vehicle::show_brand();
        cout << "Model: " << model << endl;
        cout << "Distance driven: " << mileage << " miles" << endl;
    }
};

int main()
{

    // create an object of Car class
    Car *my_car = new Car();

    // initialize variables of my_car
    my_car->brand = "Honda";
    my_car->model = "Accord";
    my_car->drive(50);

    // display object variables
    my_car->show_data();
    my_car->show_brand();

    int x = 0, y = 0, z = 0;
    jump_table( 3,
        [&]{ ++x; },
        [&]{ ++y; },
        [&]{ ++z; },
        [&]{ ++x; ++z; }
    );
    std::cout << x << y << z << "\n";

    return 0;
}